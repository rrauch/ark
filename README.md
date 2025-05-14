![Ark: Your Data. Archived. Forever.](./cover.png)

# Ark: Self-Sovereign Digital Archiving (Proof-of-Concept)

---

## 🤔 What is Ark?

Ark is an experimental, open-source project building a new model for long-term digital archiving on
the [Autonomi Network](#built-on-autonomi). Forget subscriptions and relying on third parties - Ark aims to give you
permanent control and secure ownership of your digital history.

**This repository contains a Proof-of-Concept demonstrating the core ideas and technical potential of the Ark
architecture.**

---

## 🚧 Current Status: Prototype Only

### Not Slowing Down!

v0.0.2 is out:

> The next release of Ark is out - **v0.0.2**!
>
> It’s still early days, but the foundation is getting stronger and the pieces are falling into place. There’s been a
> lot of progress under the hood in just a week - the cryptographic components are improving and things are getting more
> flexible.
>
> A couple of new user-facing things to play with:
> * **Ark Details**:  The *CLI* now lets you see detailed information about an Ark using any of its authorized keys -
    `Helm Key`, `Data Key`, `Worker Key` - or the `Ark Seed`
> * **Vault Creation**: You can now create vaults directly from the *CLI*. This includes setting which bridge is
    authorized and what type of object the vault will handle: *filesystem (POSIX/Windows)*, *email (IMAP/Gmail)*, or
    *object storage (S3)*.
>
> Overall development is progressing really well! Soon, work will start on the `Ark Engine`. Once a basic version is
> out, `Ark`s premise will start to become much clearer and more self-evident.

**Warning: This is a Proof-of-Concept and is NOT ready for storing any data.**
This code is unstable and represents an early exploration of the concepts.

The goal of this prototype is to validate the core cryptographic design, data handling flows, and interaction patterns
with the Autonomi Network.

---

## Screenshots

Creating a new Ark:
![Image](assets/poc/v0.0.1/screenshots/create2.png "creation of a new Ark")
Creating a new Vault:
![Image](assets/poc/v0.0.2/screenshots/create1.png "creation of a new Vault")
Rotate Keys:
![Image](assets/poc/v0.0.1/screenshots/rotate3.png "key rotation")
Accessing Ark Details using an authorized key:
![Image](assets/poc/v0.0.2/screenshots/show1.png "Ark Details")

more Screenshots: [v0.0.2](assets/poc/v0.0.2/screenshots/), [v0.0.1](assets/poc/v0.0.1/screenshots/)

---

## 🧠 The Vision: A New Era for Your Data

Ark is prototyping a future where:

* **You own your data, permanently:** No more recurring fees just to keep your files accessible. Pay once, and your data
  is designed to last for decades on a decentralized network.
* **You control access:** Your data is encrypted, and only you (or those you authorize) hold the keys needed for
  decryption.
* **Recovery is always in your hands:** Access and restore your entire archive any time using only a 24-word secret you
  keep safe offline - your **`Ark Seed`**.
* **Your data is secure from online threats:** A unique key system ensures that the online tools managing your archive
  cannot decrypt your sensitive data.
* **You can archive anything:** A flexible design lets you connect and archive data from almost any source.

---

## ⚙️ Technical Approach & Key Concepts

### **Your Ultimate Control: The `Ark Seed`**

Your archive's security begins with your **`Ark Seed`** - a 24-word secret you create and keep safe offline. This Seed
is the cryptographic root for everything related to your Ark. It's designed so that you can derive all other necessary
keys and locate your data on the network using *only* this Seed, ensuring recovery is always independent of any service
provider. Your `Ark Seed` *is* your recovery plan!

### **Secure Key Hierarchy**

Ark uses a layered system of keys, all derived from your `Ark Seed`. This hierarchy is designed to be both secure and
practical:

* The **`Helm Key`** is used for administrative tasks and `Worker Key` rotation.
* The **`Data Key`** is the ultimate key needed to decrypt your archived files and always stays with you.
* The **`Worker Key`** is held by the online **`Ark Engine`** software that manages your archive operations. Crucially,
  the `Worker Key` **cannot decrypt your actual data**.
* This separation means that even if the `Ark Engine` or the server it runs on is compromised, your sensitive data
  remains protected because the attacker doesn't have your `Data Key`.
* Because all keys are derived from your `Ark Seed`, you can recover or rotate (generate new) keys if needed, using only
  your original Seed.

### **Data Handling & Efficiency**

* **`Bridges`**: Modular components that connect to specific data sources (file system, IMAP, S3, etc.). They identify
  changes, break data into **content-defined chunks (CDC)**, encrypt these chunks, and stream the *encrypted data* to
  the Engine.
* **`Ark Engine`**: The core process that receives *encrypted data* from Bridges and manages their upload to Autonomi.
  The Engine never has access to your plaintext data.
* **Global Deduplication**: Ark's use of **content-defined-chunking**, combined with Autonomi's **content addressing**,
  means that if an exact chunk of data already exists anywhere on the Autonomi Network (uploaded by anyone), it doesn't
  need to be uploaded or paid for again. This makes archiving increasingly efficient network-wide.

### **Built on Autonomi**

Ark is built directly on the [Autonomi Network](https://github.com/maidsafe/autonomi/), leveraging its foundational
capabilities:

* **Permanent Data Storage:** Ark uses Autonomi's immutable data types designed for long-term persistence and the "
  pay-once-store-forever" economic model to offer archives without recurring fees.
* **Network-Wide Deduplication:** Autonomi's content addressing ensures that identical data chunks uploaded by any user,
  anywhere, are stored only once. Ark is designed to benefit directly from this.
* **Native Cryptography:** Autonomi provides the tools for deterministic key derivation and secure key management
  essential for Ark's self-sovereign design.

---

### Repository Content

This repository contains a Proof-of-Concept implementation including:

* `ark-core`: Shared library with core logic.
* `ark-cli`: Command-line interface tool.
* `ark-engine`: The core daemon process.
* `ark-transport`: Transport mechanisms for communication between `Ark Engine` & `Bridge`.
* `bridge`: An example Bridge for local filesystems.

---

## 📜 License

GNU GPLv3 - This code is experimental and provided for review and contribution. **It should not be used for production
or storing data.**

---

*Disclaimer: This is experimental software demonstrating concepts - it is not functional for real-world archiving.*
