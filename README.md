
<img src="tiara-logo.png" width="200" align="bottom" />

# Threat Intelligence Automated Research Assistant (TIARA)

In my experience, threat intel is not very well utilised in security alert triage and investigation. If an organisation is even collecting/curating information about threat actors and their methods, I have not seen many (any?) of them using this information to assist responders in their day to day monitoring work (at least not in any meaningful way).

Why is this? The MITRE ATT&CK® framework has been widely adopted by the industry, giving us a common taxonomy, and many blue teams now have their detections/alerts mapped to ATT&CK. Surely this puts us in a position to extract more value from our intel?

TIARA is an experiment to see what might be possible.

Given input containing MITRE ATT&CK® techniques, it will attempt to generate information about how known threat actors use these techniques. This information is primarily intended to assist with the analysis of security alerts.

It's a work in progress that will develop over time, hopefully to the point it can be added to [Squyre](https://github.com/gyrospectre/squyre). 

## Caveats
 - It's not intended to attribute activity. [Attribution is hard!](https://www.spgedwards.com/2014/11/whodunnit-apt-attribution-is-hard.html)
 - The only datasource used is the MITRE ATT&CK® group database (https://attack.mitre.org/groups/). This limits us to ~135, mainly state sponsored groups.

## How it works

1. Technique references are first extracted from the provided file or URL. Sub-techniques are included; as is the parent technique if it is not already present.
2. The set of techniques are then run against the MITRE ATT&CK® threat actor group database, collating the ways each group have used these methods. A list of reference report URLs is also built.
3. This information is output to a file, in JSON.

In order to increase relevance, a few filters are applied.
1. The source techniques are compared to all techniques we know each group uses. A "similarity" threshold is then applied to only use groups that are enough of a match.
2. Groups for which the source data has not been recently updated are not used.

## Compiling
```
git clone https://github.com/gyrospectre/tiara.git
cd tiara/pkg
go build .
```

## Usage
See `./tiara --help` for usage details.

An example run, with an optional technique overlap of 59% applied, and groups not updated in the past year excluded:

```
$ ./tiara -source https://blog.group-ib.com/apt41-world-tour-2021 -similarity 55 -freshness 1
                                         
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
   ''-'       '--'  '"          '--'  '"   https://github.com/gyrospectre/tiara

INFO[0001] Extracted 62 techniques from "https://blog.group-ib.com/apt41-world-tour-2021". 
INFO[01-13|13:45:31] Fetching MITRE ATT&CK... 
INFO[0003] Success, loaded 104 actor groups! Groups not updated within the last 1 years have been excluded. 
INFO[0003] Generating recommendations...                
INFO[0003] Found actor "Suckfly" with an technique overlap of 60.000000%. 
INFO[0003] Found actor "GALLIUM" with an technique overlap of 58.064516%. 
INFO[0003] Found actor "Windigo" with an technique overlap of 57.142857%. 
INFO[0003] Success! Output saved to "report".           
INFO[0003] All done.
```
The output looks something like that in [sample-report](https://github.com/gyrospectre/tiara/blob/main/sample-report).

## Todo

After some time using this with real life data and tweaking, the plan is to add TIARA as an enrichment function to Squyre (https://github.com/gyrospectre/squyre) - if any value can be realised.

Time will tell, but I suspect that the MITRE database is not going to detailed enough for this use case. If this turns out to be the case, I'd like to explore adding support for TIP platforms like MISP, EclecticIQ etc.

I'd also like to flip the logic and see what happens when you (like now,) look for groups with a minimum technique overlap, but then see what techniques *don't* overlap. Build a list and stack rank by occurrence - does this help us find activity that an actor may have performed but we didn't catch initally?

## Interpreting the Output
WIP

## Credit / Thanks
Thanks to Vesselin Bontchev and [WhoDunit](https://gitlab.com/bontchev/whodunit), the seed that originally started me thinking about TIARA!

MITRE ATT&CK® parsing uses [MaineK00n's](https://twitter.com/MaineK00n) wonderful [go-cti](https://github.com/vulsio/go-cti) project. Go check our their work!

## License
MIT

## Author
[Bill Mahony](https://www.linkedin.com/in/bill-mahony-7651866/)
