package cmd

func Run() {
	flagcheck()
	scan()

	if saveResults {
		save()
	}
}
