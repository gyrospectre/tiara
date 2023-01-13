package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/juliangruber/go-intersect"
	"github.com/parnurzeal/gorequest"
	log "github.com/sirupsen/logrus"
	"github.com/vulsio/go-cti/fetcher/attack"
	"github.com/vulsio/go-cti/models"
	"golang.org/x/exp/slices"
)

var TechRegex = regexp.MustCompile(`T\d{4}\.\d{3}|T\d{4}`)

type Actor struct {
	Name       string
	Id         string
	Techniques map[string]*Technique
	TechList   []string
	Overlap    float64
}

type Technique struct {
	Name        string
	Description string
	Citations   []string
}

type IntelReport struct {
	TechniqueInfo  map[string][]string
	FurtherReading []string
	Metadata       struct {
		Source           string
		CreatedAt        time.Time
		SourceTechniques []string
		SimilarityCutoff float64
		FreshnessCutoff  int
	}
}

func sliceDiff(groupList []string, inputList []string) []string {
	var res []string
	for _, el := range groupList {
		if !slices.Contains(inputList, el) {
			res = append(res, el)
		}
	}
	return res
}

func getData() ([]Actor, error) {
	_, attackers, err := attack.Fetch()

	if err != nil {
		return nil, err
	}
	actors := normaliseGroups(attackers)

	return actors, nil
}

func splitSubTech(techs []string) []string {
	var newTechs []string
	for _, tech := range techs {
		if strings.Contains(tech, ".") {
			newTechs = append(newTechs, strings.Split(tech, ".")[0])
		}
		newTechs = append(newTechs, tech)
	}
	return newTechs
}

func fetchUrl(url string) ([]byte, error) {
	resp, body, err := gorequest.New().Get(url).Type("text").EndBytes()
	if err != nil {
		return nil, err[0]
	}
	if resp == nil || resp.StatusCode != 200 {
		return nil, errors.New("failed to fetch data from Url")
	}

	return body, nil
}

func extractTechs(source string) ([]string, error) {
	var scanner *bufio.Scanner

	if strings.HasPrefix(source, "http") {
		result, err := fetchUrl(source)
		scanner = bufio.NewScanner(strings.NewReader(string(result)))
		if err != nil {
			return nil, err
		}
	} else {
		f, err := os.Open(source)
		scanner = bufio.NewScanner(f)
		if err != nil {
			return nil, err
		}
	}

	var extractedTechs []string
	for scanner.Scan() {
		submatchall := TechRegex.FindAllString(scanner.Text(), -1)

		for _, technique := range submatchall {
			if !slices.Contains(extractedTechs, technique) {
				extractedTechs = append(extractedTechs, technique)
			}
		}
	}
	return splitSubTech(extractedTechs), nil
}

func addOverlap(actors []Actor, techs []string) ([]Actor, error) {
	var newActors []Actor

	for _, actor := range actors {
		tmpActor := actor
		tmpActor.Overlap = float64(len(intersect.Simple(actor.TechList, techs))) * 100.0 / float64(len(actor.TechList))
		newActors = append(newActors, tmpActor)
	}

	return newActors, nil
}

func genRecommendations(actors []Actor, techs []string, freshness int, similarity float64, common bool) *IntelReport {
	sort.Slice(actors, func(i, j int) bool { return actors[i].Overlap > actors[j].Overlap })

	report := &IntelReport{}
	report.TechniqueInfo = make(map[string][]string)

	var techScope []string
	for _, grp := range actors {
		if grp.Overlap > similarity {
			log.Infof("Found actor \"%s\" with an technique overlap of %f%%.", grp.Name, grp.Overlap)

			if common {
				techScope = grp.TechList
			} else {
				techScope = sliceDiff(grp.TechList, techs)
			}

			if len(techScope) > 0 || common {
				for _, t := range techScope {
					key := fmt.Sprintf("%s (%s)", t, grp.Techniques[t].Name)
					newDesc := strings.ReplaceAll(grp.Techniques[t].Description, "Actor", grp.Name)
					report.TechniqueInfo[key] = append(report.TechniqueInfo[key], newDesc)
					if len(grp.Techniques[t].Citations) > 0 {
						for _, ref := range grp.Techniques[t].Citations {
							if !slices.Contains(report.FurtherReading, ref) {
								report.FurtherReading = append(report.FurtherReading, ref)
							}
						}
					}
				}
			}
		}
	}

	return report
}

func normaliseGroups(attackerList []models.Attacker) []Actor {
	var result []Actor

	for _, attackerObj := range attackerList {
		if strings.HasPrefix(attackerObj.Name, "G") {
			var techlist []string
			for _, technique := range attackerObj.TechniquesUsed {
				techlist = append(techlist, technique.TechniqueID)
			}
			cutoff := time.Now().Add(time.Duration(-YearsConsideredObsolete*365*24) * time.Hour)

			if attackerObj.Modified.After(cutoff) {
				normalisedGroup := &Actor{
					Name:       strings.TrimSpace(strings.Split(attackerObj.Name, ":")[1]),
					Id:         attackerObj.AttackerID,
					Techniques: buildTechList(attackerObj.TechniquesUsed, attackerObj.References),
					TechList:   techlist,
				}
				result = append(result, *normalisedGroup)
			}
		}
	}

	return result
}

func buildTechList(techs []models.TechniqueUsed, refs []models.AttackerReference) map[string]*Technique {
	finalTechs := make(map[string]*Technique)

	for _, tech := range techs {
		rawTech := &tech
		rawTech.Use = "Actor" + strings.Split(rawTech.Use, ")")[1] + ")"

		var citations []string
		if strings.Contains(rawTech.Use, "Citation: ") {
			re := regexp.MustCompile(`\(Citation:(.*?)\)`)

			submatchall := re.FindAllString(rawTech.Use, -1)
			for _, citationName := range submatchall {
				citationName = strings.Split(citationName, ": ")[1]
				citationName = strings.Trim(citationName, ")")

				fixedCitation := citationName
				for _, ref := range refs {
					if ref.SourceName == citationName {
						fixedCitation = ref.URL
					}
				}

				citations = append(citations, fixedCitation)
			}

		}

		finalTechs[rawTech.TechniqueID] = &Technique{
			Description: rawTech.Use,
			Citations:   citations,
			Name:        strings.TrimSpace(strings.Split(rawTech.Name, ":")[1]),
		}
	}
	return finalTechs
}
