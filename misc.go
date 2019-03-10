package main

// func setSessionInt(session *sessions.Session, key string, val int) {
// 	if session.Values[key] == nil {
// 		session.Values[key] = val
// 		// return 0
// 	} else {
// 		val, _ := session.Values[key].(int)
// 		val++
// 		session.Values[key] = val
// 		// return val
// 	}
// }
//
// func compSum() {
// 	sum := sha256.Sum256([]byte("hello world"))
// 	fmt.Printf("%x", sum)
// }
//
// func readLines(path string) ([]string, error) {
// 	file, err := os.Open(path)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer file.Close()
//
// 	var lines []string
// 	scanner := bufio.NewScanner(file)
// 	for scanner.Scan() {
// 		lines = append(lines, scanner.Text())
// 	}
// 	return lines, scanner.Err()
// }
//
// // writeLines writes the lines to the given file.
// func writeLines(lines []string, path string) error {
// 	file, err := os.Create(path)
// 	if err != nil {
// 		return err
// 	}
// 	defer file.Close()
//
// 	w := bufio.NewWriter(file)
// 	for _, line := range lines {
// 		fmt.Fprintln(w, line)
// 	}
// 	return w.Flush()
// }
