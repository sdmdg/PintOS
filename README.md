# Pintos Project
This repository contains my implementation of the **Pintos Operating System** for the CS2043 - Operating Systems Module.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Build](#build)
- [Testing](#testing)

## Overview

Pintos is a lightweight OS designed to run on a simulated x86 architecture. Throughout this project, I implemented various modules, incrementally enhancing the operating system's capabilities.

### Implemented Labs
1. **Threads**: Implemented scheduling algorithms, synchronization primitives (locks, semaphores, condition variables) and priority donation.
2. **User Programs**: Added support for user program execution, system calls and memory management.

## Features

- **Thread Scheduling**: Round-robin and priority-based scheduling.
- **Synchronization**: Priority donation, semaphores and condition variables.
- **System Calls**: Support for process management and file I/O.

## Build

1. Clone this repository:
   ```bash
   git clone https://github.com/sdmdg/pintos.git
   ```
2. Build the project:
    ```bash
    make
    cd pintos/src
    ```
## Testing

1. Lab 01 (Threads):
    ```bash
    cd threads/build
    make check
    ```
2. Lab 02 (User Programs):
    ```bash
    cd userprog/build
    make check
    ```
