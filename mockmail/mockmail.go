package mockmail

import (
	"fmt"
	log "github.com/sirupsen/logrus"
)

func Init(serviceEmail string, smtpAuthCredentials string) {
	mockAuthSmtp(serviceEmail, smtpAuthCredentials)
}

func mockAuthSmtp(email string, credentials string) {
	log.Info(fmt.Sprintf("Logged into smtp as %s with credentials: %s", email, credentials))
}

func SendEmailByGuid(user_guid string, subject string) {
	targetEmail := mockSelectEmail(user_guid)
	mockSendEmail(targetEmail, subject)
}

func mockSelectEmail(user_guid string) string {
	return fmt.Sprintf("example_%s@mail.to", user_guid)
}

func mockSendEmail(targetEmail string, subject string) {
	log.Warn(fmt.Sprintf("Mock target email: %s, mail subject: %s", targetEmail, subject))
}
