---
layout: default
title: "Artifact Repository & Image Security"
parent: "1. Overview of Cloud Native Security" 
nav_order: 5
permalink: /sections/overview-cloud-native-security/artifact-image-security/
---
# Artifact Repository and Image Security

Key aspects of securing artifact repositories and container images include:

*   **Repository Protection:** Ensure that container image repositories (artifact repositories) are adequately protected with strong access controls.
*   **Vulnerability Scanning:** Regularly scan images within repositories for known vulnerabilities.
*   **Digital Signatures:** Utilize digital signatures to verify the integrity and authenticity of container images before they are deployed to the cluster. This helps ensure that images have not been tampered with and originate from a trusted source.
