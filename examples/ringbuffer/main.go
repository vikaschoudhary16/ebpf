//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const qdiscClsact = "clsact"
const MAX_DNS_NAME_LENGTH = 256

type DNSQuery struct {
	RecordType uint16
	Class      uint16
	Name       [MAX_DNS_NAME_LENGTH]byte
}
type InAddr struct {
	Addr [4]byte
}
type DNSServer struct {
	IPAddr InAddr
	Port   uint16
	// 2 bytes padding
	Padding [2]byte
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 bpf ringbuffer.c -- -I /usr/include/x86_64-linux-gnu/ -I../headers
func main() {
	// List all network interfaces.
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("error listing network interfaces: %s", err)
	}

	// Filter interfaces that start with "veth".
	var vethInterfaces []net.Interface
	for _, iface := range interfaces {
		if strings.HasPrefix(iface.Name, "veth") {
			vethInterfaces = append(vethInterfaces, iface)
		}
	}

	if len(vethInterfaces) == 0 {
		log.Fatalf("No veth interfaces found")
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}

	// Loop through each veth interface and attach the programs.
	for _, iface := range vethInterfaces {
		link, err := netlink.LinkByName(iface.Name)
		if err != nil {
			log.Fatalf("getting interface %s by name: %w", iface.Name, err)
		}

		// Attach the program to INGRESS TC.
		err = attachTCProgram(link, objs.IngressProgFunc, "ingress", netlink.HANDLE_MIN_INGRESS)
		if err != nil {
			log.Fatalf("could not attach ingress TC program: %s", err)
		}
		// Attach the program to EGRESS TC.
		err = attachTCProgram(link, objs.EgressProgFunc, "egress", netlink.HANDLE_MIN_EGRESS)
		if err != nil {
			log.Fatalf("could not attach egress TC program: %s", err)
		}
	}

	redir_config_map := objs.QueryRedirectionConfig

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start a goroutine to handle user input
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print("Enter a hostname:dns-server-ip (or Ctrl+C to exit): ")
			if scanner.Scan() {
				input := scanner.Text()

				// Split the input into hostname and DNS server IP
				parts := strings.Split(input, ":")
				if len(parts) != 2 {
					log.Println("Invalid input format. Please use hostname:dns-server-ip.")
					continue
				}

				hostname := parts[0]
				dnsIP := parts[1]

				// Convert DNS server IP string to a byte array
				ip := net.ParseIP(dnsIP).To4()
				if ip == nil {
					log.Println("Invalid IP address format.")
					continue
				}

				// Update the hostname in the BPF map
				q := DNSQuery{
					Name: [256]byte{},
				}
				copy(q.Name[:], []byte(hostname))

				v := DNSServer{
					IPAddr: InAddr{
						Addr: [4]byte{ip[0], ip[1], ip[2], ip[3]},
					},
					Port: 53,
				}

				if err := redir_config_map.Put(&q, &v); err != nil {
					log.Fatalf("Failed to insert into map: %s", err)
				}

				log.Printf("Inserted hostname %s with DNS server IP %s into the map", hostname, dnsIP)
				v2 := DNSServer{}
				redir_config_map.Lookup(&q, &v2)
				log.Printf("IPAddr: %d.%d.%d.%d\n", v2.IPAddr.Addr[0], v2.IPAddr.Addr[1], v2.IPAddr.Addr[2], v2.IPAddr.Addr[3])
			}
		}
	}()

	// Block until a signal is received
	sig := <-sigChan
	fmt.Println("Received signal:", sig)

	// Cleanup or shutdown tasks
	fmt.Println("Shutting down gracefully...")

}

// attachTCProgram attaches the TC program 'prog' to link.
func attachTCProgram(link netlink.Link, prog *ebpf.Program, progName string, qdiscParent uint32) error {
	if prog == nil {
		return errors.New("cannot attach a nil program")
	}

	if err := replaceQdisc(link); err != nil {
		return fmt.Errorf("replacing clsact qdisc for interface %s: %w", link.Attrs().Name, err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    qdiscParent,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			//Priority:  option.Config.TCFilterPriority,
			Priority: 100,
		},
		Fd:           prog.FD(),
		Name:         fmt.Sprintf("%s-%s", progName, link.Attrs().Name),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("replacing tc filter: %w", err)
	}

	return nil
}

func replaceQdisc(link netlink.Link) error {
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  qdiscClsact,
	}

	return netlink.QdiscReplace(qdisc)
}

// removeTCFilters removes all tc filters from the given interface.
// Direction is passed as netlink.HANDLE_MIN_{INGRESS,INGRESS} via tcDir.
func removeTCFilters(ifName string, tcDir uint32) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}

	filters, err := netlink.FilterList(link, tcDir)
	if err != nil {
		return err
	}

	for _, f := range filters {
		if err := netlink.FilterDel(f); err != nil {
			return err
		}
	}

	return nil
}
