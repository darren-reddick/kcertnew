/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	cr "github.com/dreddick-home/certrenew/pkg/kcertrenew"
	"github.com/spf13/cobra"
)

// renewallCmd represents the renewall command
var renewallCmd = &cobra.Command{
	Use:   "renewall",
	Short: "Renew public cert for all kubeconfig files in a directory.",
	Long: `Command to renew the public certs for a user in a kubeconfig files in a directory.

The public cert data is stored base64 encoded in the users[].user.client-certificate-data field.

A filesystem root can be set and the command expects the root ca key and cert to be available under the root at /etc/kubernetes/pki 

This command will renew the client cert for a named kubeconfig file and store the new config in a new location.`,
	Run: func(cmd *cobra.Command, args []string) {
		expire, _ := cmd.Flags().GetInt("expire")
		root, _ := cmd.Flags().GetString("root")
		cr.RenewKubeconfigs(root, expire)
	},
}

func init() {
	rootCmd.AddCommand(renewallCmd)

	renewallCmd.Flags().String("output", "", "The name of the output file to write config to. Defaults to name of kubeconfig file.")
	renewallCmd.Flags().String("root", ".", "The root directory under which the path to the k8s config can be found at etc/kubernetes")
	renewallCmd.Flags().Int("expire", 12, "The number of months to set the certificate to expire in")
}
