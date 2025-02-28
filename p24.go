package p24

import (
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

type App interface {
	RegisterTransaction()
}

type P24 struct {
	App

	sandbox    bool
	merchantId int
	posId      int
	apiKey     string
	crc        string
}

type Config struct {
	Sandbox bool

	MerchantId int
	PosId      int
	ApiKey     string
	Crc        string
}

type TransactionParams struct {
	MerchantId  int    `json:"merchantId"`
	PosId       int    `json:"posId"`
	SessionId   string `json:"sessionId"`
	Amount      int    `json:"amount"`
	Currency    string `json:"currency"`
	Description string `json:"description"`
	Email       string `json:"email"`
	Country     string `json:"country"`
	Language    string `json:"language"`
	UrlReturn   string `json:"urlReturn"`
	UrlStatus   string `json:"urlStatus"`
	Sign        string `json:"sign"`
}

type NotificationParams struct {
	MerchantId   int    `json:"merchantId"`
	PosId        int    `json:"posId"`
	SessionId    string `json:"sessionId"`
	Amount       int    `json:"amount"`
	OriginAmount int    `json:"originAmount"`
	Currency     string `json:"currency"`
	OrderId      int64  `json:"orderId"`
	MethodId     int    `json:"methodId"`
	Statement    string `json:"statement"`
	Sign         string `json:"sign"`
}

type RegisterTransactionResponse struct {
	Data struct {
		Token string `json:"token"`
	}
	ResponseCode int    `json:"response_code"`
	Error        string `json:"error"`
	Code         int    `json:"code"`
}

func New(config Config) *P24 {
	p24 := &P24{
		sandbox:    config.Sandbox,
		merchantId: config.MerchantId,
		posId:      config.PosId,
		apiKey:     config.ApiKey,
		crc:        config.Crc,
	}

	return p24
}

// RegisterTransaction returns an url used to finish a registered transaction.
func (p24 *P24) RegisterTransaction(data TransactionParams) (string, error) {
	data.MerchantId = p24.merchantId
	data.PosId = p24.posId

	var url string
	if p24.sandbox {
		url = "https://sandbox.przelewy24.pl/api/v1/transaction/register"
	} else {
		url = "https://secure.przelewy24.pl/api/v1/transaction/register"
	}

	data.Sign = calculateRegistrationSignature(data.SessionId, data.MerchantId, data.Amount, data.Currency, p24.crc)

	bodyJson, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJson))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(strconv.Itoa(p24.posId), p24.apiKey)

	httpClient := &http.Client{
		Timeout: time.Second * 10,
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}

	var respBody RegisterTransactionResponse
	err = json.NewDecoder(resp.Body).Decode(&respBody)
	if err != nil {
		return "", err
	}

	if resp.StatusCode == 200 {
		if p24.sandbox {
			return fmt.Sprintf("https://sandbox.przelewy24.pl/trnRequest/%s", respBody.Data.Token), nil
		} else {
			return fmt.Sprintf("https://secure.przelewy24.pl/trnRequest/%s", respBody.Data.Token), nil
		}
	} else {
		return "", errors.New(fmt.Sprintf("Response code: %d\nError: %s", respBody.Code, respBody.Error))
	}

	//
}

func (p24 *P24) VerifyTransaction(data NotificationParams) error {
	payload := struct {
		MerchantId int    `json:"merchantId"`
		PosId      int    `json:"posId"`
		SessionId  string `json:"sessionId"`
		Amount     int    `json:"amount"`
		Currency   string `json:"currency"`
		OrderId    int64  `json:"orderId"`
		Sign       string `json:"sign"`
	}{
		MerchantId: data.MerchantId,
		PosId:      data.PosId,
		SessionId:  data.SessionId,
		Amount:     data.Amount,
		Currency:   data.Currency,
		OrderId:    data.OrderId,
		Sign:       calculateVerificationSignature(data.SessionId, data.OrderId, data.Amount, data.Currency, p24.crc),
	}

	var verificationUrl string

	if p24.sandbox {
		verificationUrl = "https://sandbox.przelewy24.pl/api/v1/transaction/verify"
	} else {
		verificationUrl = "https://secure.przelewy24.pl/api/v1/transaction/verify"
	}

	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", verificationUrl, bytes.NewBuffer(payloadJson))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(strconv.Itoa(p24.posId), p24.apiKey)

	httpClient := &http.Client{
		Timeout: time.Second * 10,
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}

	var respBody RegisterTransactionResponse
	err = json.NewDecoder(resp.Body).Decode(&respBody)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprintf("Response code: %d\nError: %s", respBody.Code, respBody.Error))
	}

	return nil
}

func calculateRegistrationSignature(sessionId string, merchantId int, amount int, currency string, crc string) string {
	sign := []byte(fmt.Sprintf(`{"sessionId":"%s","merchantId":%d,"amount":%d,"currency":"%s","crc":"%s"}`, sessionId, merchantId, amount, currency, crc))

	signHash := sha512.New384()
	signHash.Write(sign)
	hashSum := signHash.Sum(nil)

	return fmt.Sprintf("%x", hashSum)
}

func calculateVerificationSignature(sessionId string, orderId int64, amount int, currency string, crc string) string {
	sign := []byte(fmt.Sprintf(`{"sessionId":"%s","orderId":%d,"amount":%d,"currency":"%s","crc":"%s"}`, sessionId, orderId, amount, currency, crc))

	signHash := sha512.New384()
	signHash.Write(sign)
	hashSum := signHash.Sum(nil)

	return fmt.Sprintf("%x", hashSum)
}
