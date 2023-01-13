package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	Name        = "Threat Intelligence Automated Research Assistant (TIARA)"
	Description = "Tiara takes a file or URL containing Mitre ATT&CK techniques, and makes suggestions for further reading to assist with analysis."
	Source      = "https://github.com/gyrospectre/tiara"
	Art         = `                                         
         .--.                             
         |__|                             
     .|  .--.          .-,.--.            
   .' |_ |  |    __    |  .-. |    __     
 .'     ||  | .:--.'.  | |  | | .:--.'.   
'--.  .-'|  |/ |   \ | | |  | |/ |   \ |  
   |  |  |  |'" __ | | | |  '- '" __ | |  
   |  |  |__| .'.''| | | |      .'.''| |  
   |  '.'    / /   | |_| |     / /   | |_ 
   |   /     \ \._,\ '/|_|     \ \._,\ '/ 
   ''-'       '--'  '"          '--'  '"  `
)

var (
	// Defaults
	YearsConsideredObsolete = 2
	SimilarityCutoff        = 50.0
	SourceFile              = "inputdata.txt"
	OutputFile              = "report"
)

func Usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "\n.~:+[ %s ]+:~.", Name)
	fmt.Fprintf(flag.CommandLine.Output(), "%s %s\n\n", Art, Source)
	fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n\n")
	flag.PrintDefaults()
	fmt.Fprintf(flag.CommandLine.Output(), "\n\n")
}

func main() {
	flag.Usage = Usage

	similarity := flag.Float64("similarity", SimilarityCutoff, "Minimum technique overlap as a percentage")
	freshness := flag.Int("freshness", YearsConsideredObsolete, "Filter out groups not updated in this number of years")
	source := flag.String("source", SourceFile, "The source from which to extract techniques. Either a file or a URL")

	flag.Parse()
	fmt.Printf("%s %s\n\n", Art, Source)

	techs, err := extractTechs(*source)
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("Extracted %d techniques from \"%s\".", len(techs), *source)

	actors, err := getData()
	if err != nil {
		log.Fatal("Failed to fetch Cyber Threat Intelligence. err: %w", err)
	}

	actors, _ = addOverlap(actors, techs)
	log.Infof("Success, loaded %d actor groups! Groups not updated within the last %d years have been excluded.", len(actors), *freshness)

	log.Info("Generating recommendations...")
	intel := genRecommendations(actors, techs, *freshness, *similarity, true)

	intel.Metadata.Source = *source
	intel.Metadata.CreatedAt = time.Now()
	intel.Metadata.SimilarityCutoff = *similarity
	intel.Metadata.FreshnessCutoff = *freshness
	intel.Metadata.SourceTechniques = techs

	f, _ := os.Create(OutputFile)
	out := bufio.NewWriter(f)

	jsonString, _ := json.MarshalIndent(intel, "", "    ")
	out.WriteString(string(jsonString))

	out.Flush()
	f.Close()

	log.Infof("Success! Output saved to \"%s\".", OutputFile)

	log.Info("All done.\n\n")
	os.Exit(0)
}
