use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::task::AbortHandle;

enum Event {
    Progress {
        task_id: usize,
        newly_completed: usize,
    },
    Start(usize),
    Stop(usize),
    Complete(usize),
    Failed(usize),
    Add {
        task_id: usize,
        parent_id: usize,
        total: usize,
        label: Option<String>,
    },
}

impl Event {
    fn add(task_id: usize, parent_id: usize, total: usize, label: Option<String>) -> Self {
        Self::Add {
            task_id,
            parent_id,
            total,
            label,
        }
    }

    fn progress(task_id: usize, newly_completed: usize) -> Self {
        Self::Progress {
            task_id,
            newly_completed,
        }
    }

    fn start(task_id: usize) -> Self {
        Self::Start(task_id)
    }

    fn stop(task_id: usize) -> Self {
        Self::Stop(task_id)
    }

    fn complete(task_id: usize) -> Self {
        Self::Complete(task_id)
    }

    fn failed(task_id: usize) -> Self {
        Self::Failed(task_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    id: usize,
    label: Option<String>,
    total: usize,
    completed: usize,
    status: Status,
    subreports: Vec<Self>,
}

impl Report {
    pub fn id(&self) -> usize {
        self.id
    }

    pub fn label(&self) -> Option<&str> {
        self.label.as_ref().map(|s| s.as_str())
    }

    pub fn total(&self) -> usize {
        self.subreports.iter().map(|r| r.total()).sum::<usize>() + self.total
    }

    pub fn completed(&self) -> usize {
        self.subreports.iter().map(|r| r.completed()).sum::<usize>() + self.completed
    }

    pub fn percent_completed(&self) -> f64 {
        let total = self.total();
        if self.total() == 0 {
            0f64
        } else {
            let completed = self.completed();
            1f64 / total as f64 * completed as f64
        }
    }

    pub fn status(&self) -> Status {
        self.status
    }

    pub fn subreports(&self) -> &Vec<Self> {
        &self.subreports
    }

    fn get_mut(&mut self, task_id: usize) -> Option<&mut Self> {
        if task_id == self.id {
            Some(self)
        } else {
            self.subreports.iter_mut().find_map(|r| r.get_mut(task_id))
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Status {
    WAITING,
    ACTIVE,
    SUCCESS,
    FAILURE,
}

pub struct Progress {
    rx: watch::Receiver<Report>,
    tx: watch::Sender<Report>,
}

impl Clone for Progress {
    fn clone(&self) -> Self {
        Self {
            rx: self.tx.subscribe(),
            tx: self.tx.clone(),
        }
    }
}

impl Progress {
    pub(crate) fn new(total: usize, label: impl Into<Option<String>>) -> (Self, Task) {
        let (task, report_tx, report_rx) = Task::new(total, label.into());

        (
            Self {
                rx: report_rx,
                tx: report_tx,
            },
            task,
        )
    }

    pub fn latest(&mut self) -> Report {
        self.rx.borrow_and_update().clone()
    }
}

impl Future for Progress {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut fut = Box::pin(this.rx.changed());

        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(()),
            Poll::Ready(Err(_)) => Poll::Pending,
        }
    }
}

pub struct Task {
    id: usize,
    counter: Arc<AtomicUsize>,
    event_tx: mpsc::Sender<Event>,
    reporter_abort_handle: Option<AbortHandle>,
}

impl Drop for Task {
    fn drop(&mut self) {
        if let Some(abort_handle) = self.reporter_abort_handle.take() {
            abort_handle.abort();
        }
    }
}

impl Task {
    fn new(
        total: usize,
        label: impl Into<Option<String>>,
    ) -> (Self, watch::Sender<Report>, watch::Receiver<Report>) {
        let mut report = Report {
            id: 1,
            label: label.into(),
            total,
            completed: 0,
            status: Status::WAITING,
            subreports: vec![],
        };
        let counter = Arc::new(AtomicUsize::new(2));
        let (report_tx, report_rx) = watch::channel(report.clone());

        let (event_tx, mut event_rx) = mpsc::channel(64);

        let reporter_abort_handle = {
            let report_tx = report_tx.clone();
            tokio::spawn(async move {
                while !report_tx.is_closed() && !event_rx.is_closed() {
                    match event_rx.recv().await {
                        Some(event) => {
                            if report_tx.is_closed() {
                                break;
                            }
                            let mut modified = false;
                            match event {
                                Event::Add {
                                    task_id,
                                    parent_id,
                                    total,
                                    label,
                                } => {
                                    if let Some(parent) = report.get_mut(parent_id) {
                                        parent.subreports.push(Report {
                                            id: task_id,
                                            label,
                                            total,
                                            completed: 0,
                                            status: Status::WAITING,
                                            subreports: vec![],
                                        });
                                        modified = true;
                                    }
                                }
                                Event::Complete(task_id) => {
                                    if let Some(rep) = report.get_mut(task_id) {
                                        if rep.status != Status::SUCCESS {
                                            rep.status = Status::SUCCESS;
                                            modified = true;
                                        }
                                    }
                                }
                                Event::Failed(task_id) => {
                                    if let Some(rep) = report.get_mut(task_id) {
                                        if rep.status != Status::FAILURE {
                                            rep.status = Status::FAILURE;
                                            modified = true;
                                        }
                                    }
                                }
                                Event::Start(task_id) => {
                                    if let Some(rep) = report.get_mut(task_id) {
                                        if rep.status != Status::ACTIVE {
                                            rep.status = Status::ACTIVE;
                                            modified = true;
                                        }
                                    }
                                }
                                Event::Stop(task_id) => {
                                    if let Some(rep) = report.get_mut(task_id) {
                                        if rep.status != Status::WAITING {
                                            rep.status = Status::WAITING;
                                            modified = true;
                                        }
                                    }
                                }
                                Event::Progress {
                                    task_id,
                                    newly_completed,
                                } => {
                                    if let Some(rep) = report.get_mut(task_id) {
                                        if newly_completed > 0 {
                                            if rep.status != Status::ACTIVE {
                                                rep.status = Status::ACTIVE;
                                            }
                                            rep.completed += newly_completed;
                                            modified = true;
                                        }
                                    }
                                }
                            }

                            if modified {
                                let _ = report_tx.send(report.clone());
                            }
                        }
                        None => {
                            break;
                        }
                    }
                }
            })
        }
        .abort_handle();

        (
            Self {
                id: 1,
                counter,
                event_tx,
                reporter_abort_handle: Some(reporter_abort_handle),
            },
            report_tx,
            report_rx,
        )
    }

    pub fn child(&mut self, total: usize, label: impl Into<Option<String>>) -> Task {
        let child_id = self.counter.fetch_add(1, Ordering::Acquire);
        self.send(Event::add(child_id, self.id, total, label.into()));
        Task {
            id: child_id,
            counter: self.counter.clone(),
            event_tx: self.event_tx.clone(),
            reporter_abort_handle: None,
        }
    }

    pub fn start(&mut self) {
        self.send(Event::start(self.id));
    }

    pub fn stop(&mut self) {
        self.send(Event::stop(self.id));
    }

    pub fn complete(self) {
        self.send(Event::complete(self.id));
    }

    pub fn failure(self) {
        self.send(Event::failed(self.id));
    }

    fn add(&mut self, newly_completed: usize) {
        self.send(Event::progress(self.id, newly_completed));
    }

    fn send(&self, event: Event) {
        if let Err(err) = self.event_tx.try_send(event) {
            let event = err.into_inner();
            let tx = self.event_tx.clone();
            tokio::spawn(async move {
                let _ = tx.send(event).await;
            });
        }
    }

    /*pub fn message(&self, message: impl AsRef<str>) {
        self.inner.info(|| message.as_ref().to_string())
    }*/
}

impl std::ops::AddAssign<usize> for Task {
    fn add_assign(&mut self, rhs: usize) {
        self.add(rhs);
    }
}
