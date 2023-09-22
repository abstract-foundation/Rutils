package rcp

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// respRCP is made for ResponseRCP ONLY
func (n *ServerRCP) respRPC(w http.ResponseWriter, r *http.Request) {

}

// msgRCP is made for MessageRCP ONLY
func (n *ServerRCP) msgRCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var message MessageRCP
	if err := decoder.Decode(&message); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	messageResponse := ResponseRCP{
		Sender:   fmt.Sprintf("%s:%d", n.Host, n.Port),
		Accepted: false,
		Content:  "nil",
	}

	for _, handler := range n.MessageHandlers[message.Endpoint] {
		if accepted, reason := handler(message); !accepted {
			messageResponse.Content = reason
			break
		}
	}

	if messageResponse.Content == "nil" {
		messageResponse.Accepted = true
	}

	// Send the response as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(messageResponse); err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}
}
