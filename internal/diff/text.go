package diff

import (
	"fmt"
	"strings"
)

// Text renders the diff for people:
//
//   - host 172.28.0.30
//   - 80/tcp http nginx "Welcome"
//     ~ 127.0.0.1
//   - 8787/tcp http nginx
//     ~ 3001/tcp http.title: "Installation - Gitea" -> "Gitea"
func (d *Diff) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "scan %s (%d hosts, %d services) -> scan %s (%d hosts, %d services)\n",
		d.Old.StartedAt.Format("2006-01-02 15:04:05"), d.Old.Hosts, d.Old.Services,
		d.New.StartedAt.Format("2006-01-02 15:04:05"), d.New.Hosts, d.New.Services)
	for _, w := range d.Warnings {
		fmt.Fprintf(&b, "warning: %s\n", w)
	}
	if d.Summary.Empty() {
		b.WriteString("no changes\n")
		return b.String()
	}
	b.WriteString("\n")
	for _, h := range d.Hosts {
		switch h.Kind {
		case New:
			fmt.Fprintf(&b, "+ host %s\n", h.Address)
		case Gone:
			fmt.Fprintf(&b, "- host %s\n", h.Address)
		default:
			fmt.Fprintf(&b, "~ %s\n", h.Address)
		}
		for _, s := range h.Services {
			fmt.Fprintf(&b, "  %s %d/%s %s\n", sign(s.Kind), s.Port, s.Proto, s.Label)
			for _, f := range s.Changes {
				fmt.Fprintf(&b, "      %s: %s -> %s\n", f.Field, quote(f.Old), quote(f.New))
			}
		}
	}
	s := d.Summary
	fmt.Fprintf(&b, "\n%d new hosts, %d gone hosts, %d new services, %d gone services, %d changed services\n",
		s.NewHosts, s.GoneHosts, s.NewServices, s.GoneServices, s.ChangedServices)
	return b.String()
}

func sign(k Kind) string {
	switch k {
	case New:
		return "+"
	case Gone:
		return "-"
	}
	return "~"
}

func quote(s string) string {
	if s == "" {
		return "(none)"
	}
	return fmt.Sprintf("%q", s)
}
