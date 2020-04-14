// Copyright 2020 The gVisor Authors.
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

package udp_icmp_error_propagation

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

func TestUdpIcmpErrorPropagation(t *testing.T) {
	for _, tt := range []struct {
		name     string
		icmpType header.ICMPv4Type
		icmpCode uint8
	}{
		{"Port unreachable after connect", header.ICMPv4DstUnreachable, header.ICMPv4PortUnreachable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dut := tb.NewDUT(t)
			defer dut.TearDown()

			remoteFd, remotePort := dut.CreateBoundSocket(unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.ParseIP("0.0.0.0"))
			defer dut.Close(remoteFd)

			conn := tb.NewUDPIPv4(t, tb.UDP{DstPort: &remotePort}, tb.UDP{SrcPort: &remotePort})
			defer conn.Close()

			dut.Connect(remoteFd, conn.LocalAddr())

			dut.Send(remoteFd, nil, 0)
			udp, err := conn.Expect(tb.UDP{}, time.Second)
			if err != nil {
				t.Fatalf("did not receive message from DUT: %s", err)
			}

			conn.SendICMP(&tb.ICMPv4{Type: &tt.icmpType, Code: &tt.icmpCode}, udp)

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = dut.SendWithErrno(ctx, remoteFd, nil, 0)
			if err == nil || err == syscall.Errno(0) {
				t.Fatalf("DUT send after ICMP error should have errored")
			}
			if err != unix.ECONNREFUSED {
				t.Fatalf("DUT send after ICMP error resulted in error (%[1]d) %[1]v, expected (%[2]d) %[2]v", err, unix.ECONNREFUSED)
			}
		})
	}
}
