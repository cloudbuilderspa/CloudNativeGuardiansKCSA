---
layout: default
title: Home
nav_order: 1
description: "KCSA Certification Study Guide - Your comprehensive guide to preparing for the KCSA exam."
---

For the Spanish version, please see [README_es.md](README_es.md).
---

# KCSA Certification Study Guide (CloudNativeGuardiansKCSA)

## Purpose

Welcome to the CloudNativeGuardiansKCSA repository. This space is designed to serve as a comprehensive study guide and self-assessment platform to prepare you for the **KCSA (Kubernetes and Cloud Native Security Associate)** certification. Here you will find study materials, practical examples, and per-section exams to help you master the key concepts of cloud native security.

## Repository Structure

The content of this repository is organized into thematic sections, each covering a specific domain of the KCSA exam. All sections are located within the `sections/` directory.

### Main Sections:

1.  **[1. Overview of Cloud Native Security](/CloudNativeGuardiansKCSA/sections/overview-cloud-native-security/)** 
    *   ([Visión General de la Seguridad Cloud Native - Español](/CloudNativeGuardiansKCSA/es/sections/vision-general-seguridad-cloud-native/))
2.  **`2_Cluster_Setup`**: Secure configuration of Kubernetes clusters.
3.  **`3_Cluster_Hardening`**: Techniques and best practices for strengthening the security of Kubernetes clusters.
4.  **`4_System_Hardening`**: Strengthening security at the operating system and cluster node level.
5.  **`5_Minimize_Microservice_Vulnerabilities`**: Strategies to reduce vulnerabilities in microservices.
6.  **`6_Supply_Chain_Security`**: Securing the software supply chain, from code to deployment.
7.  **`7_Monitoring_Logging_and_Runtime_Security`**: Monitoring, logging, and runtime security for cloud native applications.

### Bilingual Content Organization:

To facilitate study for a wider audience, the study material within each section is available in two languages:

*   **Spanish:** Spanish content files have the `_es.md` suffix (e.g., `main_concepts_es.md`).
*   **English:** English content files have the `_en.md` suffix (e.g., `main_concepts_en.md`).

Each section may also include:
*   Lab files (e.g., `lab_ejemplo.yml` or specific ones like `lab_np.yml` and `lab_pss.yml` in section 1) to practice the learned concepts.
*   An interactive exam script `exam.py`.

## How to Use the Practice Exams

Each thematic section includes a Python script (`exam.py`) that allows you to take a practice exam to assess your knowledge of the topics in that section.

To run an exam:

1.  **Navigate to the desired section directory:**
    ```bash
    cd sections/SECTION_NAME/
    # Example:
    # cd sections/1_Overview of Cloud Native Security/
    ```

2.  **Run the exam script:**
    Use `python` or `python3` depending on your system configuration.
    ```bash
    python exam.py
    # or
    # python3 exam.py
    ```

3.  **Select the Language:**
    At the beginning, the script will ask you to choose the language for the exam. You can enter:
    *   `en` for English.
    *   `es` for Spanish.

Follow the on-screen instructions to complete the exam. At the end, you will receive your score.

## Contributions

Contributions are welcome! If you find errors, have suggestions to improve the material, want to add new questions to the exams, or propose additional content, please feel free to:

*   Open an **Issue** to discuss the changes.
*   Submit a **Pull Request** with your improvements.

Together we can make this repository an even better resource for the community.

