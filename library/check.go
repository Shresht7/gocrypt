package library

//	Panic if error
func Check(err error) {
	if err != nil {
		panic(err)
	}
}
