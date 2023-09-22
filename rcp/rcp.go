package rcp

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
	// Optional
	Content string `json:"content"`
}

type ServerRCP struct {
	Host string
	Port int

	Peers            *PeerList
	MessageHandlers  map[string][]func(message MessageRCP) (bool, string)
	ResponseHandlers map[string]func(message ResponseRCP) bool
}

func NewServerRCP(host string, port int) *ServerRCP {
	return &ServerRCP{
		Host:             host,
		Port:             port,
		Peers:            &PeerList{},
		MessageHandlers:  make(map[string][]func(message MessageRCP) (bool, string)),
		ResponseHandlers: make(map[string]func(message ResponseRCP) bool),
	}
}

func (rcp *ServerRCP) RegisterMessageHandler(endpoint string, handler func(message MessageRCP) (bool, string)) {
	// WARNINING : NEVER ADD DUPLICATE HANDLERS (THIS WILL CAUSE SEVERE BUGS)

	if _, contains := rcp.MessageHandlers[endpoint]; !contains {
		rcp.MessageHandlers[endpoint] = make([]func(message MessageRCP) (bool, string), 0)
	}

	rcp.MessageHandlers[endpoint] = append(rcp.MessageHandlers[endpoint], handler)
}

func (rcp *ServerRCP) RemoveMessageHandler(endpoint string) {
	if _, contains := rcp.MessageHandlers[endpoint]; contains {
		delete(rcp.MessageHandlers, endpoint)
	}
}

func (rcp *ServerRCP) RegisterResponseHandler(endpoint string, handler func(message ResponseRCP) bool) {
	rcp.ResponseHandlers[endpoint] = handler
}

func (rcp *ServerRCP) RemoveResponseHandler(endpoint string) {
	if _, contains := rcp.ResponseHandlers[endpoint]; contains {
		delete(rcp.ResponseHandlers, endpoint)
	}
}
