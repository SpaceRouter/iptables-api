package server

func Init(host string, port string, savePath string) error {
	r := NewRouter(savePath)
	return r.Run(host + ":" + port)
}
