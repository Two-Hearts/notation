// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package trustpolicy

import (
	"path/filepath"

	. "github.com/notaryproject/notation/test/e2e/internal/notation"
	"github.com/notaryproject/notation/test/e2e/internal/utils"
	. "github.com/notaryproject/notation/test/e2e/suite/common"
	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("notation trust policy verification level test", func() {
	It("strict level with expired signature", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			artifact := GenerateArtifact("e2e-expired-signature", "")

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("expiry validation failed.",
					VerifyFailed)
		})
	})

	It("strict level with expired authentic timestamp", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			artifact := GenerateArtifact("e2e-with-expired-cert", "")

			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("trustpolicy.json", false),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2EConfigPath, "localkeys", "expired_e2e.crt")),
			)

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("authenticTimestamp validation failed",
					VerifyFailed)
		})
	})

	It("strict level with invalid authenticity", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("trustpolicy.json", false),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2ELocalKeysDir, "new_e2e.crt")),
			)

			// the artifact signed with a different cert from the cert in
			// trust store.
			artifact := GenerateArtifact("e2e-valid-signature", "")

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("authenticity validation failed",
					VerifyFailed)
		})
	})

	It("strict level with invalid integrity", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			artifact := GenerateArtifact("e2e-invalid-signature", "")

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("integrity validation failed",
					VerifyFailed)
		})
	})

	It("permissive level with expired signature", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("permissive_trustpolicy.json", false))

			artifact := GenerateArtifact("e2e-expired-signature", "")

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("expiry was set to \"log\" and failed with error: digital signature has expired").
				MatchKeyWords(VerifySuccessfully)
		})
	})

	It("permissive level with expired authentic timestamp", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			artifact := GenerateArtifact("e2e-with-expired-cert", "")

			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("permissive_trustpolicy.json", false),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2EConfigPath, "localkeys", "expired_e2e.crt")),
			)

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("Warning: authenticTimestamp was set to \"log\"",
					"after certificate \"O=Internet Widgits Pty Ltd,ST=Some-State,C=AU\" validity period, it was expired at \"Tue, 27 Jun 2023 06:10:00 +0000\"").
				MatchKeyWords(VerifySuccessfully)
		})
	})

	It("permissive level with invalid authenticity", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("permissive_trustpolicy.json", false),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2ELocalKeysDir, "new_e2e.crt")),
			)

			// the artifact signed with a different cert from the cert in
			// trust store.
			artifact := GenerateArtifact("e2e-valid-signature", "")

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("authenticity validation failed",
					VerifyFailed)
		})
	})

	It("permissive level with invalid integrity", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("permissive_trustpolicy.json", false))

			artifact := GenerateArtifact("e2e-invalid-signature", "")

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("integrity validation failed",
					VerifyFailed)
		})
	})

	It("audit level with expired signature", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("audit_trustpolicy.json", false))

			artifact := GenerateArtifact("e2e-expired-signature", "")

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("digital signature has expired",
					"expiry was set to \"log\"").
				MatchKeyWords(VerifySuccessfully)
		})
	})

	It("audit level with expired authentic timestamp", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			artifact := GenerateArtifact("e2e-with-expired-cert", "")

			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("audit_trustpolicy.json", false),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2EConfigPath, "localkeys", "expired_e2e.crt")),
			)

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("Warning: authenticTimestamp was set to \"log\"",
					"after certificate \"O=Internet Widgits Pty Ltd,ST=Some-State,C=AU\" validity period, it was expired at \"Tue, 27 Jun 2023 06:10:00 +0000\"").
				MatchKeyWords(VerifySuccessfully)
		})
	})

	It("audit level with invalid authenticity", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("audit_trustpolicy.json", false),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2ELocalKeysDir, "new_e2e.crt")),
			)

			// the artifact signed with a different cert from the cert in
			// trust store.
			artifact := GenerateArtifact("e2e-valid-signature", "")

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("Warning: authenticity was set to \"log\"",
					"the signature's certificate chain does not contain any trusted certificate").
				MatchKeyWords(VerifySuccessfully)
		})
	})

	It("audit level with invalid integrity", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("audit_trustpolicy.json", false))

			artifact := GenerateArtifact("e2e-invalid-signature", "")

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("integrity validation failed",
					VerifyFailed)
		})
	})

	It("skip level with invalid integrity", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("skip_trustpolicy.json", false))

			artifact := GenerateArtifact("e2e-invalid-signature", "")

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchKeyWords("Trust policy is configured to skip signature verification")
		})
	})

	It("strict level with Expiry overridden as log level", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("override_strict_trustpolicy.json", false))

			artifact := GenerateArtifact("e2e-expired-signature", "")

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("digital signature has expired",
					"expiry was set to \"log\"").
				MatchKeyWords(VerifySuccessfully)
		})
	})

	It("strict level with Authentic timestamp overridden as log level", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			artifact := GenerateArtifact("e2e-with-expired-cert", "")

			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("override_strict_trustpolicy.json", false),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2EConfigPath, "localkeys", "expired_e2e.crt")),
			)

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("Warning: authenticTimestamp was set to \"log\"",
					"after certificate \"O=Internet Widgits Pty Ltd,ST=Some-State,C=AU\" validity period, it was expired at \"Tue, 27 Jun 2023 06:10:00 +0000\"").
				MatchKeyWords(VerifySuccessfully)
		})
	})

	It("strict level with Authenticity overridden as log level", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("override_strict_trustpolicy.json", false),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2ELocalKeysDir, "new_e2e.crt")),
			)

			// the artifact signed with a different cert from the cert in
			// trust store.
			artifact := GenerateArtifact("e2e-valid-signature", "")

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("Warning: authenticity was set to \"log\"",
					"the signature's certificate chain does not contain any trusted certificate").
				MatchKeyWords(VerifySuccessfully)
		})
	})

	It("permissive level with Expiry overridden as enforce level", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("override_permissive_trustpolicy.json", false))

			artifact := GenerateArtifact("e2e-expired-signature", "")

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("expiry validation failed.",
					VerifyFailed)
		})
	})

	It("permissive level with Authentic timestamp overridden as enforce level", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("override_permissive_trustpolicy.json", false))

			artifact := GenerateArtifact("e2e-with-expired-cert", "")

			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("trustpolicy.json", false),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2EConfigPath, "localkeys", "expired_e2e.crt")),
			)

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("authenticTimestamp validation failed",
					VerifyFailed)
		})
	})

	It("permissive level with Authenticity overridden as log level", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("override_permissive_trustpolicy.json", false),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2ELocalKeysDir, "new_e2e.crt")),
			)

			artifact := GenerateArtifact("e2e-valid-signature", "")

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("Warning: authenticity was set to \"log\"",
					"the signature's certificate chain does not contain any trusted certificate").
				MatchKeyWords(VerifySuccessfully)
		})
	})

	It("permissive level with Integrity overridden as log level", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("override_integrity_for_permissive_trustpolicy.json", false),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2ELocalKeysDir, "new_e2e.crt")),
			)

			artifact := GenerateArtifact("e2e-valid-signature", "")

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords(`"integrity" verification can not be overridden in custom signature verification`)
		})
	})

	It("audit level with Expiry overridden as enforce level", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("override_audit_trustpolicy.json", false))

			artifact := GenerateArtifact("e2e-expired-signature", "")

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("expiry validation failed.",
					VerifyFailed)
		})
	})

	It("audit level with Authentic timestamp overridden as enforce level", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("override_audit_trustpolicy.json", false))

			artifact := GenerateArtifact("e2e-with-expired-cert", "")

			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("trustpolicy.json", false),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2EConfigPath, "localkeys", "expired_e2e.crt")),
			)

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("authenticTimestamp validation failed",
					VerifyFailed)
		})
	})

	It("audit level with Authenticity overridden as enforce level", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("override_audit_trustpolicy.json", false),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2ELocalKeysDir, "new_e2e.crt")),
			)

			// the artifact signed with a different cert from the cert in
			// trust store.
			artifact := GenerateArtifact("e2e-valid-signature", "")

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-d").
				MatchErrKeyWords("authenticity validation failed",
					VerifyFailed)
		})
	})
})
