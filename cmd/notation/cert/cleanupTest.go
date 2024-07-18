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

package cert

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/notaryproject/notation-go/config"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation/cmd/notation/internal/truststore"
	"github.com/spf13/cobra"
)

type certCleanupTestOpts struct {
	name string
}

func certCleanupTestCommand(opts *certCleanupTestOpts) *cobra.Command {
	if opts == nil {
		opts = &certCleanupTestOpts{}
	}
	command := &cobra.Command{
		Use:   "cleanup-test [flags] <common_name>",
		Short: "Clean up the test key and corresponding certificate created by the 'generated-test' command. Use it only for testing purposes.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("missing certificate common_name")
			}
			opts.name = args[0]
			return nil
		},
		Long: `Clean up the test key and corresponding certificate created by the 'generated-test' command. Use it only for testing purposes.

Example - Clean up a test key and corresponding certificate named "wabbit-networks.io":
  notation cert cleanup-test "wabbit-networks.io"
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cleanupTestCert(opts)
		},
	}

	return command
}

func cleanupTestCert(opts *certCleanupTestOpts) error {
	name := opts.name
	if !truststore.IsValidFileName(name) {
		return errors.New("name needs to follow [a-zA-Z0-9_.-]+ format")
	}

	// 1. remove key and certificate files from LocalKeyPath
	relativeKeyPath, relativeCertPath := dir.LocalKeyPath(name)
	configFS := dir.ConfigFS()
	keyPath, err := configFS.SysPath(relativeKeyPath)
	if err != nil {
		return err
	}
	certPath, err := configFS.SysPath(relativeCertPath)
	if err != nil {
		return err
	}
	if err := os.Remove(keyPath); err != nil {
		return err
	}
	if err := os.Remove(certPath); err != nil {
		return err
	}
	fmt.Printf("Successfully deleted %s and %s\n", filepath.Base(keyPath), filepath.Base(certPath))

	// 2. remove from signingkeys.json config
	exec := func(s *config.SigningKeys) error {
		_, err := s.Remove(name)
		return err
	}
	if err := config.LoadExecSaveSigningKeys(exec); err != nil {
		return err
	}
	fmt.Printf("Successfully removed %q from signingkeys.json\n", name)

	// 3. remove from trust store
	if err := truststore.DeleteCert("ca", name, filepath.Base(certPath), true); err != nil {
		return err
	}

	return nil
}
