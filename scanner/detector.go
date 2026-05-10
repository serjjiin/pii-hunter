package scanner

import (
	"regexp"
	"strings"

	"github.com/piihunter/pii-hunter/models"
)

var (
	reCPF        = regexp.MustCompile(`\b\d{3}[\.\s]?\d{3}[\.\s]?\d{3}[-\.\s]?\d{2}\b`)
	reCNPJ       = regexp.MustCompile(`\b\d{2}[\.\s]?\d{3}[\.\s]?\d{3}[\/\.\s]?\d{4}[-\.\s]?\d{2}\b`)
	reEmail      = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
	rePhone      = regexp.MustCompile(`(\+55\s?)?\(?\d{2}\)?\s?\d{4,5}[\-\s]?\d{4}`)
	reCreditCard = regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`)
	reCEP        = regexp.MustCompile(`\b\d{5}[-\s]?\d{3}\b`)
	reBirthDate  = regexp.MustCompile(`\b\d{4}[-\/]\d{2}[-\/]\d{2}\b|\b\d{2}[-\/]\d{2}[-\/]\d{4}\b`)
)

var columnHeuristics = map[string]models.PIIType{
	"nome": models.PIITypeName, "name": models.PIITypeName, "full_name": models.PIITypeName,
	"nome_completo": models.PIITypeName, "primeiro_nome": models.PIITypeName,
	"sobrenome": models.PIITypeName, "first_name": models.PIITypeName, "last_name": models.PIITypeName,

	"endereco": models.PIITypeAddress, "address": models.PIITypeAddress, "logradouro": models.PIITypeAddress,
	"rua": models.PIITypeAddress, "avenida": models.PIITypeAddress,
	"complemento": models.PIITypeAddress, "bairro": models.PIITypeAddress,

	"data_nasc": models.PIITypeBirthDate, "nascimento": models.PIITypeBirthDate,
	"birth_date": models.PIITypeBirthDate, "birthdate": models.PIITypeBirthDate,
	"dob": models.PIITypeBirthDate, "dt_nasc": models.PIITypeBirthDate,

	"cpf": models.PIITypeCPF, "documento": models.PIITypeCPF, "doc_number": models.PIITypeCPF,

	"email": models.PIITypeEmail, "e_mail": models.PIITypeEmail,
	"email_address": models.PIITypeEmail, "correio": models.PIITypeEmail,

	"telefone": models.PIITypePhone, "celular": models.PIITypePhone, "fone": models.PIITypePhone,
	"phone": models.PIITypePhone, "mobile": models.PIITypePhone, "tel": models.PIITypePhone,
}

// DetectValue analisa um valor e retorna os tipos de PII detectados por regex.
// Aplica expressões regulares compiladas para cada tipo de dado pessoal conhecido.
func DetectValue(value string) []models.PIIType {
	var found []models.PIIType
	if m := reCPF.FindString(value); m != "" && !allSameDigit(onlyDigits(m)) {
		found = append(found, models.PIITypeCPF)
	}
	if reCNPJ.MatchString(value) {
		found = append(found, models.PIITypeCNPJ)
	}
	if reEmail.MatchString(value) {
		found = append(found, models.PIITypeEmail)
	}
	if rePhone.MatchString(value) {
		found = append(found, models.PIITypePhone)
	}
	if reCreditCard.MatchString(value) {
		found = append(found, models.PIITypeCreditCard)
	}
	if reCEP.MatchString(value) {
		found = append(found, models.PIITypeCEP)
	}
	if reBirthDate.MatchString(value) {
		found = append(found, models.PIITypeBirthDate)
	}
	return found
}

// DetectByColumnName retorna tipos de PII inferidos pelo nome da coluna.
// A análise é case-insensitive e baseada em heurísticas pré-definidas.
func DetectByColumnName(columnName string) []models.PIIType {
	if piiType, ok := columnHeuristics[strings.ToLower(columnName)]; ok {
		return []models.PIIType{piiType}
	}
	return nil
}

// Anonymize retorna uma versão mascarada do valor para exibição em relatórios.
// Nunca retorna o valor original — preserva apenas partes não sensíveis.
func Anonymize(value string, piiType models.PIIType) string {
	switch piiType {
	case models.PIITypeCPF:
		if len(value) < 5 {
			return strings.Repeat("*", len(value))
		}
		return "***" + value[3:len(value)-2] + "**"
	case models.PIITypeEmail:
		at := strings.Index(value, "@")
		if at <= 0 {
			return strings.Repeat("*", len(value))
		}
		return string(value[0]) + strings.Repeat("*", at-1) + value[at:]
	case models.PIITypeCreditCard:
		if len(value) < 4 {
			return strings.Repeat("*", len(value))
		}
		return "**** **** **** " + value[len(value)-4:]
	default:
		return strings.Repeat("*", len(value))
	}
}

func onlyDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func allSameDigit(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}
