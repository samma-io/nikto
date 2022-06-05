# Samma Security Scanner Nikto

![Samma-io!](/assets/samma_logo.png)




## Samma Security Scanners
This scanner is part of the Samma Security Scanners

The Samma Security Scanners are all small openspurce scanners. That have ben docerixed and print there result in JSON format.
The result is then sent to ElasticSerarch for storage and displayed using Kibana ore Grafana.

To see all the scanners please go to [Samma.io](https://samma.io)

## Getting results

![Log flow!](/assets/samma_setup.drawio.png)

Samma Security Scanners can send the result to Elasticsearch. Use the ready Filebeat to start up beside the scanner. The folder /out is shared between the contaniers and filebeat reads the result and send the data to Elasticsearch.
![K8s!](/assets/samma-k8s.drawio.png)

In a Kubernetes Cluster you can also use your own logpipline. Here the scanners will print out the result in JSON format that are then read by the log pods and sent to Elasticsearch ore other logs tools like Splunk.




## Start with Highground 
Highground is a colelctions of Elasticsearch ,Kibana and Grafana that is put toghter. 
Its ready so that the different scanners can send there result into Elasticsearch and then use the pre ready dashbourds to show the result.

![K8s!](/assets/dash1.png)
![K8s!](/assets/tsunami.png)
![K8s!](/assets/findings.png)
![K8s!](/assets/grafana.png)


You can send result with the attaced filebeat that send logs directly ore use your normal stput log flow.
Then save the logs in the samma-io index to use our pre dashbourds.


## Start with console
All Samma Security scanners can be run from the command line to scan then output the result in JSON. This make its easy to integrate the scanner into diffrent piplines but also test the scanners localy


```
docker run sammascanner/nikto -e TARGET=samma.io 
```

## Docker-compose
All repos has a responding docker compose to setup and test localy on a developer machine. Start by sarting up highground to get the dashbourds ready.
Then start the scanner you want to run against your targets.


## Kubernetes 
All repos has manifest so that you can deploy your scanners into your own kubernetes cluster. The manifest are mostly testet aginst minkube but will work against any kubernetes cluster.

## Helm
I helm repo is avalibel to deploy scanners with helm. This can be used to example deploy scanner into the cluster in the pipeline ore into a productions scanner cluster.

[Samma Helm Charts](https://github.com/samma-io/helm)

## Help
Help is provided by the bravops team at [Braveops](https://braveops.io/samma) 



## Nikto
Nikto is a applications scanner that will look for new XSS and Other security problems witha webbapplications.

[Nikto](https://cirt.net/)

### Profiles 
The Nikto scanner can be tuned to run diffrent tuning against the target. Depending on what you want to test 


## Settings
All Samma Securoty Scanners are set with ENV varables. 


```
- TARGET=1.1.1.1
```
Set the target this can be a IP ore Domain

```
- TUNING=23
```
Set the profile to use [Tuning](https://github.com/sullo/nikto/wiki/Scan-Tuning)

```
- PORT=443
```
The port you want to test 

```
- SAMMA_IO_SCANNER=name
```
Set what scanner use used this i passed on and you can name it to any string


```
- SAMMA_IO_ID=g23dE222
```
Set a ID of the scanner if you want to combine mult scanners and search for them this can ge used. 
You can also add the gitsha if you used the scanners in a pipline


```
- SAMMA_IO_TAGS=['scanner','prod']
```
Tags to be used with the scanner


```
- SAMMA_IO_JSON={"extra":"value"}
```
Extra jason that will be passed to Elastic 

```
- WRITE_TO_FILE="true"
```

Write the output to file this need to be activated if you use filebeat so send logs to Elasticsearch


adding tekton
