package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

var signature = "header signature"

var secretToken = "your secret token"

// json to struct で変換し作成
type Webhooks struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Resource string `json:"resource"`
	Data     struct {
		ID              string    `json:"id"`
		Resource        string    `json:"resource"`
		Status          string    `json:"status"`
		Amount          int       `json:"amount"`
		Tax             int       `json:"tax"`
		Customer        string    `json:"customer"`
		PaymentDeadline time.Time `json:"payment_deadline"`
		PaymentDetails  struct {
			Type             string      `json:"type"`
			Email            string      `json:"email"`
			Store            string      `json:"store"`
			ConfirmationCode interface{} `json:"confirmation_code"`
			Receipt          string      `json:"receipt"`
			InstructionsURL  string      `json:"instructions_url"`
		} `json:"payment_details"`
		PaymentMethodFee int         `json:"payment_method_fee"`
		Total            int         `json:"total"`
		Currency         string      `json:"currency"`
		Description      interface{} `json:"description"`
		CapturedAt       time.Time   `json:"captured_at"`
		ExternalOrderNum interface{} `json:"external_order_num"`
		Metadata         struct {
		} `json:"metadata"`
		CreatedAt          time.Time     `json:"created_at"`
		AmountRefunded     int           `json:"amount_refunded"`
		Locale             string        `json:"locale"`
		Session            interface{}   `json:"session"`
		CustomerFamilyName interface{}   `json:"customer_family_name"`
		CustomerGivenName  interface{}   `json:"customer_given_name"`
		Refunds            []interface{} `json:"refunds"`
		RefundRequests     []interface{} `json:"refund_requests"`
	} `json:"data"`
	CreatedAt time.Time   `json:"created_at"`
	Reason    interface{} `json:"reason"`
}

func checkHmac(key, data, signeture []byte) bool {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	expectMac := h.Sum(nil)
	return hmac.Equal([]byte(signeture), expectMac)
}

func main() {
	// 実装コード ginを使用している
	// signature := c.GetHeader("X-Komoju-Signature")

	// var webhook Webhooks
	// json の取得
	// c.BindJSON(&webhook)

	webhook := Webhooks{} // 本来はここでデータを入れる

	data, _ := json.Marshal(webhook) // バイト配列に変換

	if checkHmac([]byte(secretToken), []byte(signature), data) {
		fmt.Println("正しい値です")
	} else {
		fmt.Println("正しい値ではありません。")
	}
}

/*
	[Ruby sample]
	require "sinatra"

	WEBHOOK_SECRET_TOKEN = "keep it secret, keep it safe!"

	post '/hook' do
		request_body = request.body.read
		signature = OpenSSL::HMAC.hexdigest('sha256', WEBHOOK_SECRET_TOKEN, request_body)
		return 400 unless Rack::Utils.secure_compare(signature, request.env["HTTP_X_KOMOJU_SIGNATURE"])

		"Hello World"
	end
*/
