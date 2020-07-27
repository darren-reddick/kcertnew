/*
Copyright © 2020 NAME HERE dreddick.home@gmail.com

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

// renewCmd represents the renew command
var renewCmd = &cobra.Command{
	Use:   "renew",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		kubeconfig, _ := cmd.Flags().GetString("kubeconfig")
		expire, _ := cmd.Flags().GetInt("expire")
		root, _ := cmd.Flags().GetString("root")
		output := kubeconfig
		if o, _ := cmd.Flags().GetString("output"); o != "" {
			output = o
		}
		cr.Renew(kubeconfig, root, output, expire)
	},
}

func init() {
	rootCmd.AddCommand(renewCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// renewCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	renewCmd.Flags().String("kubeconfig", "kubelet.conf", "The name of the kubeconfig file to renew certs in")
	renewCmd.Flags().String("output", "", "The name of the output file to write config to. Defaults to name of kubeconfig file.")
	renewCmd.Flags().String("root", ".", "The root directory under which the path to the k8s config can be found at etc/kubernetes")
	renewCmd.Flags().Int("expire", 12, "The number of months to set the certificate to expire in")
}
