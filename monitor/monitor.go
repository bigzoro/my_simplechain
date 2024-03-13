package monitor

import (
	"encoding/json"
	"fmt"
	"github.com/simplechain-org/go-simplechain/p2p"
	"github.com/simplechain-org/go-simplechain/rpc"
	"log"
	"net/http"
)

type MonitorService struct {
	port string
}

type PublicMonitorAPI struct {
	monitorService *MonitorService
}

func New(port string) *MonitorService {
	return &MonitorService{port}
}

func NewPublicMonitorAPI(monitorService *MonitorService) *PublicMonitorAPI {
	return &PublicMonitorAPI{monitorService}
}
func (service *MonitorService) Protocols() []p2p.Protocol { return []p2p.Protocol{} }

func (service *MonitorService) APIs() []rpc.API {
	return []rpc.API{
		{
			Namespace: "monitor",
			Version:   "1.0",
			Service:   NewPublicMonitorAPI(service),
			Public:    true,
		},
	}
}

func (service *MonitorService) Start(p2pServer *p2p.Server) error {
	http.HandleFunc("/info", getRunningStatus)
	addr := fmt.Sprintf(":%s", service.port)
	log.Println("Listen ", addr)
	err := http.ListenAndServe(addr, nil)
	if err != nil {
		return err
	}
	return nil
}

func (service *MonitorService) Stop() error {
	return nil
}

func getRunningStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	setHeader(w)
	m := map[string]bool{
		"ProcessStatus": true,
	}
	resDate(w, m)
}

func resDate(w http.ResponseWriter, data interface{}) {
	s, err := json.Marshal(data)
	if err != nil {
		resErr(err, w)
		return
	}
	fmt.Fprintf(w, string(s))
}
func setHeader(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")
}

func resErr(err error, w http.ResponseWriter) {
	res := RespErr{
		Code: 400,
		Msg:  err.Error(),
	}
	s, _ := json.Marshal(res)

	_, _ = fmt.Fprintf(w, string(s))
}

type RespErr struct {
	Code int
	Msg  string
}
