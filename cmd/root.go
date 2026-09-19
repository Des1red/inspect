package cmd

func Run() {
	flagcheck()
	target()
	ping()
	ports()
	result()

	if saveResults {
		save()
	}
}
