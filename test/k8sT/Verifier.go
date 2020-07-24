// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8sTest

import (
	"fmt"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

const (
	script = "bpf/verifier-test.sh"
)

var _ = Describe("K8sVerifier", func() {
	var kubectl *helpers.Kubectl

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		// We don't check the returned error because Cilium could
		// already be removed (e.g., first test to run).
		kubectl.DeleteResource("ds", fmt.Sprintf("-n %s cilium", helpers.CiliumNamespace))
		ExpectCiliumNotRunning(kubectl)

		testVerifierManifest := helpers.ManifestGet(kubectl.BasePath(), "test-verifier.yaml")
		res := kubectl.ApplyDefault(testVerifierManifest)
		res.ExpectSuccess("Unable to apply %s", testVerifierManifest)
		err := kubectl.WaitForSinglePod(helpers.DefaultNamespace, "test-verifier", helpers.HelperTimeout)
		Expect(err).Should(BeNil(), "test-verifier pod not ready after timeout")

		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, "test-verifier", "make -C /cilium/bpf clean V=0")
		res.ExpectSuccess("Failed to clean up bpf/ tree")
	})

	AfterFailed(func() {
		res := kubectl.Exec("kubectl describe pod")
		GinkgoPrint(res.CombineOutput().String())
	})

	AfterAll(func() {
		kubectl.DeleteResource("pod", "test-verifier")
	})

	SkipItIf(helpers.SkipGKEQuarantined, "Runs the kernel verifier against Cilium's BPF datapath", func() {
		By("Building BPF objects from the tree")
		res := kubectl.ExecPodCmd(helpers.DefaultNamespace, "test-verifier", "make -C /cilium/bpf V=0")
		res.ExpectSuccess("Expected compilation of the BPF objects to succeed")
		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, "test-verifier", "make -C /cilium/tools/maptool/")
		res.ExpectSuccess("Expected compilation of maptool to succeed")

		By("Running the verifier test script")
		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, "test-verifier", "/cilium/test/bpf/verifier-test.sh")
		res.ExpectSuccess("Expected the kernel verifier to pass for BPF programs")
	})
})
