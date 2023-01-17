package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
)

func main() {
	//GetDisallowList()
	//ExtractList()
	categories := GetAllCategories()
	CreateFirewallConfig(categories, "/tmp/pffilter/bad_sites.conf")

}

func GetDisallowList() {
	fmt.Println("Opening local temp directory...")
	if err := os.RemoveAll("/tmp/pffilter"); err != nil {
		panic(err)
	}
	if err := os.Mkdir("/tmp/pffilter", os.ModePerm); err != nil {
		panic(err)
	}

	file, err := os.Create("/tmp/pffilter/data.tar.gz")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	fmt.Println("...ok!")
	resp, err := http.Get("http://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	io.Copy(file, resp.Body)
}

func ExtractList() {
	curr, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	if err := os.Chdir("/tmp/pffilter"); err != nil {
		panic(err)
	}
	if err := os.RemoveAll("/tmp/pffilter/blacklists"); err != nil {
		panic(err)
	}
	cmd := exec.Command("tar", "-x", "-z", "-f", "/tmp/pffilter/data.tar.gz")
	if err := cmd.Run(); err != nil {
		panic(err.Error())
	}
	if err := os.Chdir(curr); err != nil {
		panic(err)
	}
}

func GetAllCategories() []string {
	dirs, err := os.ReadDir("/tmp/pffilter/blacklists")
	if err != nil {
		panic(err)
	}
	var results []string
	for _, dir := range dirs {
		if !dir.Type().IsDir() {
			continue
		}
		results = append(results, dir.Name())
	}
	return results
}

func CreateFirewallConfig(categories []string, fileName string) {
	os.Remove(fileName)
	file, err := os.Create(fileName)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	w := bufio.NewWriter(file)
	for _, category := range categories {
		fmt.Printf("Processing category: %s\n", category)
		handle, err := os.Open("/tmp/pffilter/blacklists/" + category + "/domains")
		if err != nil {
			panic(err)
		}
		scanner := bufio.NewScanner(handle)
		scanner.Split(bufio.ScanLines)
		lineCount := 0
		for scanner.Scan() {
			line := fmt.Sprintf(`local-data: "%s 60 IN A 10.10.10.1" local-data: "%s IN AAAA ::10.10.10.1"`+"\n", scanner.Text(), scanner.Text())
			if _, err := w.Write([]byte(line)); err != nil {
				panic(err)
			}
			if err := w.Flush(); err != nil {
				panic(err)
			}
			lineCount++
			if lineCount%50000 == 0 {
				fmt.Printf("%d records processed.\n", lineCount)
			}
		}
		handle.Close()
		fmt.Printf("Category %s complete!\n", category)
	}
}
