package rutils

type MessageRCP struct {
	Domain   string `json:"domain"`
	Sequence string `json:"sequence"`

	Content string `json:"content"`

	/* BETA RCP FEATURES */
	ContentType string `json:"ctype"`
	Endpoint    string `json:"endpoint"`

	// As cryptographic addresses
	Sender    string `json:"sender"`
	Receiver  string `json:"receiver"`
	Signature string `json:"signature"`
}

type ResponseRCP struct {
	Sender   string `json:"sender"`
	Accepted bool   `json:"accepted"`
}

type ServerRCP struct {
	Host string
	Port int

	Peers            []string
	MessageHandlers  map[string]func(message MessageRCP)
	ResponseHandlers map[string]func(message ResponseRCP)
}

func NewServerRCP(host string, port int) *ServerRCP {
	return &ServerRCP{
		Host:             host,
		Port:             port,
		Peers:            make([]string, 0),
		MessageHandlers:  make(map[string]func(message MessageRCP)),
		ResponseHandlers: make(map[string]func(message ResponseRCP)),
	}
}

func (rcp *ServerRCP) RegisterMessageHandler(endpoint string, handler func(message MessageRCP)) {
	rcp.MessageHandlers[endpoint] = handler
}

func (rcp *ServerRCP) RemoveMessageHandler(endpoint string) {
	if _, contains := rcp.MessageHandlers[endpoint]; contains {
		delete(rcp.MessageHandlers, endpoint)
	}
}

func (rcp *ServerRCP) RegisterResponseHandler(endpoint string, handler func(message ResponseRCP)) {
	rcp.ResponseHandlers[endpoint] = handler
}

func (rcp *ServerRCP) RemoveResponseHandler(endpoint string) {
	if _, contains := rcp.ResponseHandlers[endpoint]; contains {
		delete(rcp.ResponseHandlers, endpoint)
	}
}
