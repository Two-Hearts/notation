# Notation

[![Go Report Card](https://goreportcard.com/badge/github.com/notaryproject/notation)](https://goreportcard.com/report/github.com/notaryproject/notation)
[![codecov](https://codecov.io/gh/notaryproject/notation/branch/main/graph/badge.svg)](https://codecov.io/gh/notaryproject/notation)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/notaryproject/notation/badge)](https://api.securityscorecards.dev/projects/github.com/notaryproject/notation)

Notation is a CLI project to add signatures as standard items in the OCI registry ecosystem, and to build a set of simple tooling for signing and verifying these signatures. This should be viewed as similar security to checking git commit signatures, although the signatures are generic and can be used for additional purposes. Notation is an implementation of the [Notary Project specifications][notaryproject-specs].

You can find the Notary Project [README](https://github.com/notaryproject/.github/blob/main/README.md) to learn about the overall Notary Project.

> [!NOTE]
> The documentation for installing Notation CLI is available [here](https://notaryproject.dev/docs/user-guides/installation/cli/).

## Table of Contents

  - [Quick Start](#quick-start)
  - [Community](#community)
    - [Development and Contributing](#development-and-contributing)
    - [Notary Project Community Meeting](#notary-project-community-meeting)
  - [Release Management](#release-management)
  - [Support](#support)
  - [Code of Conduct](#code-of-conduct)
  - [License](#license)

## Quick Start

- [Quick start: Sign and validate a container image](https://notaryproject.dev/docs/quickstart-guides/quickstart-sign-image-artifact/)
- [Try out Notation in this Killercoda interactive sandbox environment](https://killercoda.com/notaryproject/scenario/notation)
- Build, sign, and verify container images using Notation with [Azure Key Vault](https://docs.microsoft.com/azure/container-registry/container-registry-tutorial-sign-build-push?wt.mc_id=azurelearn_inproduct_oss_notaryproject) or [AWS Signer](https://docs.aws.amazon.com/signer/latest/developerguide/container-workflow.html)

## Community

Notary Project is a [CNCF Incubating project](https://www.cncf.io/projects/notary/). We :heart: your contribution.

### Development and Contributing

- [Build Notation from source code](/building.md)
- [Governance for Notary Project](https://github.com/notaryproject/.github/blob/master/GOVERNANCE.md)
- [Maintainers and reviewers list](https://github.com/notaryproject/notation/blob/main/CODEOWNERS)
- [Contributing Guide](https://github.com/notaryproject/.github/blob/main/CONTRIBUTING.md)
- Regular conversations for Notary Project occur on the [Cloud Native Computing Slack](https://slack.cncf.io/) **notary-project** channel.

### Notary Project Community Meeting

You can choose one of the following two meeting series based on your time zone ([Convert the UTC time to your local time](https://dateful.com/convert/utc)).

- APAC-friendly series: Every 2 weeks on Tuesday from 1:30 AM to 2:30 AM UTC at [Zoom meetng room 92845115383](https://zoom.us/j/92845115383). Please download and import the [iCalendar (.ics) file](https://zoom.us/meeting/tJYlc-yprz4pEtfURgkU87H92Lp5_tEUFUlU/ics?icsToken=DFsuxg27fSEsMo7tewAALAAAAGAjUyl-OF5plM9lOFCrpHnZXosEXk5n-tLtsqKh536tFi9N6wUbHvDObIuPsqNHNdm01l7wM7eyL1d_rDAwMDAwMQ&meetingMasterEventId=3KMpeJ5TS6G9a3N4vuLuHg) to your calendar system.
- U.S.-friendly series: Every 2 weeks on Wednesday from 4:00 PM to 5:00 PM UTC at [Zoom meetng room 95363269801](https://zoom.us/j/95363269801). Please download and import the [iCalendar (.ics) file](https://www.zoom.us/meeting/tJEuceqqqDIiGtUQKXiRMH44tFHULzhkHZ-T/ics?meetingMasterEventId=5QOyHuxhS0KKE5L-X-w41A) to your calendar system.

Please see the [CNCF Calendar](https://www.cncf.io/calendar/) for details. You can log in to hackmd.io to add your topics to the [meeting agenda](https://hackmd.io/@EG2api1FTUudGEK6PMjvuQ/rk30ceMAyl). 

## Release Management

The Notation release process is defined in [RELEASE_MANAGEMENT.md](RELEASE_MANAGEMENT.md#supported-releases).

## Support

Support for the Notation project is defined in [supported releases](RELEASE_MANAGEMENT.md#supported-releases).

## Code of Conduct

This project has adopted the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/master/code-of-conduct.md). See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for further details.

## License

This project is covered under the Apache 2.0 license. You can read the license [here](LICENSE).

[notation-releases]:      https://github.com/notaryproject/notation/releases
[notaryproject-specs]:         https://github.com/notaryproject/notaryproject
[artifact-manifest]:      https://github.com/oras-project/artifacts-spec/blob/main/artifact-manifest.md
[cncf-distribution]:      https://github.com/oras-project/distribution
