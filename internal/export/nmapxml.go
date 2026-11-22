package export

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/Inner-Savages/silence-on-the-wire/internal/result"
)

// The subset of nmap's -oX format that importers (DefectDojo's "Nmap Scan"
// among them) read, rebuilt from the nmap fields kept in the result. The
// scan itself may have been many nmap processes; this is one document.
type (
	xmlRun struct {
		XMLName  xml.Name    `xml:"nmaprun"`
		Scanner  string      `xml:"scanner,attr"`
		Args     string      `xml:"args,attr"`
		Start    int64       `xml:"start,attr"`
		Version  string      `xml:"version,attr"`
		Format   string      `xml:"xmloutputversion,attr"`
		Hosts    []xmlHost   `xml:"host"`
		Finished xmlFinished `xml:"runstats>finished"`
	}
	xmlFinished struct {
		Time int64 `xml:"time,attr"`
	}
	xmlHost struct {
		Status    xmlState      `xml:"status"`
		Address   xmlAddress    `xml:"address"`
		Hostnames xmlHostnames  `xml:"hostnames"` // always present: importers iterate it
		Ports     []xmlPort     `xml:"ports>port"`
		Extra     []xmlExtraPts `xml:"ports>extraports"`
	}
	xmlState struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	}
	xmlAddress struct {
		Addr string `xml:"addr,attr"`
		Type string `xml:"addrtype,attr"`
	}
	xmlHostnames struct {
		Names []xmlHostname `xml:"hostname"`
	}
	xmlHostname struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	}
	xmlPort struct {
		Proto   string     `xml:"protocol,attr"`
		Port    int        `xml:"portid,attr"`
		State   xmlState   `xml:"state"`
		Service xmlService `xml:"service"`
	}
	xmlService struct {
		Name      string   `xml:"name,attr"`
		Product   string   `xml:"product,attr,omitempty"`
		Version   string   `xml:"version,attr,omitempty"`
		ExtraInfo string   `xml:"extrainfo,attr,omitempty"`
		Tunnel    string   `xml:"tunnel,attr,omitempty"`
		CPE       []string `xml:"cpe"`
	}
	xmlExtraPts struct {
		State string `xml:"state,attr"`
		Count int    `xml:"count,attr"`
	}
)

// WriteNmapXML writes the nmap part of a scan as nmap XML.
func WriteNmapXML(w io.Writer, s *result.Scan) error {
	run := xmlRun{
		Scanner: "nmap", Args: "nmap " + strings.Join(s.Settings.NmapArgs, " "),
		Start: s.StartedAt.Unix(), Version: "silence-on-the-wire", Format: "1.05",
		Finished: xmlFinished{Time: s.FinishedAt.Unix()},
	}
	for _, h := range s.Hosts {
		addr, err := netip.ParseAddr(h.Address)
		if err != nil {
			return fmt.Errorf("host %q: %w", h.Address, err)
		}
		xh := xmlHost{Status: xmlState{h.State, h.Reason}, Address: xmlAddress{Addr: h.Address, Type: "ipv6"}}
		if addr.Is4() {
			xh.Address.Type = "ipv4"
		}
		for _, n := range h.Hostnames {
			xh.Hostnames.Names = append(xh.Hostnames.Names, xmlHostname{n, "user"})
		}
		for _, p := range h.Services {
			xh.Ports = append(xh.Ports, xmlPort{
				Proto: p.Proto, Port: p.Port, State: xmlState{p.State, p.Reason},
				Service: xmlService{p.Name, p.Product, p.Version, p.ExtraInfo, p.Tunnel, p.CPE},
			})
		}
		for _, e := range h.ExtraPorts {
			xh.Extra = append(xh.Extra, xmlExtraPts{e.State, e.Count})
		}
		run.Hosts = append(run.Hosts, xh)
	}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(run); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}
