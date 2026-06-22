package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	apiv1 "github.com/dns3l/dns3l-core/api/v1"
	"github.com/rodaine/table"
)

var ansiEscapeRegexp = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func WriteJSON(out io.Writer, body []byte) error {
	body = append([]byte(nil), body...)
	if len(body) == 0 {
		_, err := fmt.Fprintln(out, "{}")
		return err
	}
	_, err := out.Write(body)
	if err != nil {
		return err
	}
	if body[len(body)-1] != '\n' {
		_, err = fmt.Fprintln(out)
	}
	return err
}

func DecodeJSON[T any](body []byte) (T, error) {
	var value T
	if err := json.Unmarshal(body, &value); err != nil {
		return value, fmt.Errorf("decode API response: %w", err)
	}
	return value, nil
}

func PrintInfo(out io.Writer, info apiv1.ServerInfo, color bool) error {
	rows := [][]string{}
	if info.Version != nil {
		rows = append(rows, []string{"daemon", info.Version.Daemon})
		rows = append(rows, []string{"api", info.Version.API})
	}
	if info.Contact != nil {
		rows = append(rows, []string{"contact url", info.Contact.URL})
		rows = append(rows, []string{"contact email", strings.Join(info.Contact.EMail, ", ")})
	}
	if info.Renewal != nil {
		lastRun := ""
		if info.Renewal.LastRun != nil {
			lastRun = info.Renewal.LastRun.Format(time.RFC3339Nano)
		}
		rows = append(rows, []string{"renewal last run", lastRun})
		rows = append(rows, []string{"renewal successful", fmt.Sprint(info.Renewal.Successful)})
		rows = append(rows, []string{"renewal failed", fmt.Sprint(info.Renewal.Failed)})
	}
	return printKeyValues(out, rows, color)
}

func PrintDNSHandlers(out io.Writer, handlers []apiv1.DNSHandlerInfo, color bool) error {
	tbl := newOutputTable(out, "ID", "NAME", "FEATURES", "ZONE_NESTING")
	for _, h := range handlers {
		tbl.AddRow(h.ID, h.Name, strings.Join(h.Feature, ","), boolText(h.ZoneNesting, color))
	}
	tbl.Print()
	return nil
}

func PrintDNSRootzones(out io.Writer, rootzones []apiv1.DNSRootzoneInfo, _ bool) error {
	tbl := newOutputTable(out, "ROOT", "AUTODNS", "ACMEDNS", "CA")
	for _, rz := range rootzones {
		tbl.AddRow(rz.Root, rz.AutoDNS, rz.AcmeDNS, strings.Join(rz.CA, ","))
	}
	tbl.Print()
	return nil
}

func PrintCAs(out io.Writer, cas []apiv1.CAInfo, color bool) error {
	tbl := newOutputTable(out, "ID", "NAME", "TYPE", "ACME", "ENABLED", "VALID", "ISSUED", "ROOTZONES")
	for _, ca := range cas {
		tbl.AddRow(
			ca.ID, ca.Name, ca.Type, boolText(ca.IsAcme, color), boolText(ca.Enabled, color),
			ca.TotalValid, ca.TotalIssued, strings.Join(ca.Rootzones, ","))
	}
	tbl.Print()
	return nil
}

func PrintCA(out io.Writer, ca apiv1.CAInfo, color bool) error {
	return printKeyValues(out, [][]string{
		{"id", ca.ID},
		{"name", ca.Name},
		{"description", ca.Description},
		{"type", ca.Type},
		{"acme", boolText(ca.IsAcme, color)},
		{"enabled", boolText(ca.Enabled, color)},
		{"valid", fmt.Sprint(ca.TotalValid)},
		{"issued", fmt.Sprint(ca.TotalIssued)},
		{"url", ca.URL},
		{"roots", ca.Roots},
		{"rootzones", strings.Join(ca.Rootzones, ", ")},
	}, color)
}

func PrintCerts(out io.Writer, certs []apiv1.CertInfo, color bool) error {
	tbl := newOutputTable(out, "NAME", "VALID", "VALID_TO", "WILDCARD", "CLAIMED_BY", "ISSUER", "RENEWALS", "ACCESSES")
	for _, cert := range certs {
		claimedBy := strings.TrimSpace(cert.ClaimedBy.Name)
		if cert.ClaimedBy.EMail != "" {
			claimedBy = strings.TrimSpace(claimedBy + " <" + cert.ClaimedBy.EMail + ">")
		}
		tbl.AddRow(
			cert.Name, boolText(cert.Valid, color), cert.ValidTo, boolText(cert.Wildcard, color),
			claimedBy, cert.IssuerCN, cert.RenewCount, cert.AccessCount)
	}
	tbl.Print()
	return nil
}

func PrintCert(out io.Writer, cert apiv1.CertInfo, color bool) error {
	return printKeyValues(out, [][]string{
		{"name", cert.Name},
		{"valid", boolText(cert.Valid, color)},
		{"valid to", cert.ValidTo},
		{"claimed on", cert.ClaimedOn},
		{"claimed by", strings.TrimSpace(cert.ClaimedBy.Name + " <" + cert.ClaimedBy.EMail + ">")},
		{"wildcard", boolText(cert.Wildcard, color)},
		{"subject cn", cert.SubjectCN},
		{"issuer cn", cert.IssuerCN},
		{"serial", cert.Serial},
		{"next renewal", cert.NextRenewal},
		{"renew count", fmt.Sprint(cert.RenewCount)},
		{"last access", cert.LastAccess},
		{"access count", fmt.Sprint(cert.AccessCount)},
	}, color)
}

func PrintCertResources(out io.Writer, resources apiv1.CertResources, check bool, color bool) error {
	first := true
	for _, name := range pemResourceOrder {
		value := resourceByName(resources, name)
		if strings.TrimSpace(value) == "" {
			continue
		}
		if check {
			if err := ValidatePEM([]byte(value)); err != nil {
				return fmt.Errorf("validate PEM resource %s: %w", name, err)
			}
		}
		if !first {
			if _, err := fmt.Fprintln(out); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(out, pemResourceCaption(name, color)); err != nil {
			return err
		}
		if _, err := fmt.Fprint(out, value); err != nil {
			return err
		}
		if !strings.HasSuffix(value, "\n") {
			if _, err := fmt.Fprintln(out); err != nil {
				return err
			}
		}
		first = false
	}
	return nil
}

func pemResourceCaption(name string, color bool) string {
	caption := pemResourceLabels[name]
	if caption == "" {
		caption = name
	}
	caption = "######## " + caption + " ########"
	if !color {
		return caption
	}
	return "\033[1;36m" + caption + "\033[0m"
}

func PrintGenericJSON(out io.Writer, body []byte, color bool) error {
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		_, writeErr := out.Write(body)
		return writeErr
	}
	return printAny(out, value, color)
}

func printAny(out io.Writer, value any, color bool) error {
	switch typed := value.(type) {
	case map[string]any:
		return printObjectTable(out, typed, color)
	case []any:
		return printSliceTable(out, typed, color)
	default:
		_, err := fmt.Fprintln(out, scalarText(typed, color))
		return err
	}
}

func scalarText(value any, color bool) string {
	switch v := value.(type) {
	case bool:
		return boolText(v, color)
	case []any:
		parts := make([]string, 0, len(v))
		for _, elem := range v {
			parts = append(parts, scalarText(elem, false))
		}
		return strings.Join(parts, ", ")
	case map[string]any:
		data, _ := json.Marshal(v)
		return string(data)
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func printKeyValues(out io.Writer, rows [][]string, _ bool) error {
	tbl := newOutputTable(out, "FIELD", "VALUE").WithPrintHeaders(false)
	for _, row := range rows {
		if len(row) < 2 || strings.TrimSpace(row[1]) == "" {
			continue
		}
		tbl.AddRow(row[0]+":", row[1])
	}
	tbl.Print()
	return nil
}

func printObjectTable(out io.Writer, obj map[string]any, color bool) error {
	keys := sortedMapKeys(obj)
	tbl := newOutputTable(out, "FIELD", "VALUE")
	for _, key := range keys {
		tbl.AddRow(key, scalarText(obj[key], color))
	}
	tbl.Print()
	return nil
}

func printSliceTable(out io.Writer, values []any, color bool) error {
	if len(values) == 0 {
		tbl := newOutputTable(out, "VALUE")
		tbl.Print()
		return nil
	}

	headers := mapSliceHeaders(values)
	if len(headers) == 0 {
		tbl := newOutputTable(out, "VALUE")
		for _, value := range values {
			tbl.AddRow(scalarText(value, color))
		}
		tbl.Print()
		return nil
	}

	tbl := newOutputTable(out, headers...)
	for _, value := range values {
		obj, ok := value.(map[string]any)
		if !ok {
			tbl.AddRow(scalarText(value, color))
			continue
		}
		row := make([]interface{}, len(headers))
		for i, header := range headers {
			row[i] = scalarText(obj[header], color)
		}
		tbl.AddRow(row...)
	}
	tbl.Print()
	return nil
}

func mapSliceHeaders(values []any) []string {
	headerSet := map[string]struct{}{}
	for _, value := range values {
		obj, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		for key := range obj {
			headerSet[key] = struct{}{}
		}
	}
	headers := make([]string, 0, len(headerSet))
	for header := range headerSet {
		headers = append(headers, header)
	}
	sort.Strings(headers)
	return headers
}

func sortedMapKeys(obj map[string]any) []string {
	keys := make([]string, 0, len(obj))
	for key := range obj {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func newOutputTable(out io.Writer, headers ...string) table.Table {
	headerValues := make([]interface{}, len(headers))
	for i, header := range headers {
		headerValues[i] = header
	}
	return table.New(headerValues...).
		WithWriter(out).
		WithPadding(2).
		WithWidthFunc(visibleWidth)
}

func visibleWidth(value string) int {
	return len([]rune(ansiEscapeRegexp.ReplaceAllString(value, "")))
}

func boolText(value bool, color bool) string {
	text := "false"
	code := "31"
	if value {
		text = "true"
		code = "32"
	}
	if !color {
		return text
	}
	return "\033[" + code + "m" + text + "\033[0m"
}

func SupportsColor(file *os.File) bool {
	stat, err := file.Stat()
	if err != nil {
		return false
	}
	if stat.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	term := strings.ToLower(os.Getenv("TERM"))
	return term != "" && term != "dumb"
}
