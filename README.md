# NinjaOne Scripts - Various useful [PowerShell](https://microsoft.com/powershell) scripts for [NinjaOne](https://ninjaone.com/) software

## Who am I?
I am David Szpunar ([@dszp](https://github.com/dszp)) the owner and CEO of a managed IT services provider in the US Midwest with a past history of dabbling with scripts and programming as a support technician for over 20 years.

## What is this?
Each folder is a separate [PowerShell](https://microsoft.com/powershell) script that is in some way applicable to running on devices or via the API using the [NinjaOne]() platform. Most scripts are documented through comments at the top and often require some level of configuration or parameters to use fully. Please understand the code you run, I make no claim or warranty or fitness for any particular purpose!

Scripts that are intended to be run on Windows endpoints are generally written for PowerShell 5.1, while scripts that access the API are written primarily for [PowerShell 7](https://docs.microsoft.com/en-us/powershell/scripting/whats-new/what-s-new-in-powershell-71?view=powershell-7.1) and are mostly untested on earlier versions. API scripts will make use of the [NinjaOne PowerShell module](https://github.com/homotechsual/NinjaOne).

## Generic MSP Scripts
Many of the scripts above are perfectly usable, or usable with very minimal modification, on nearly any Remote Monitoring & Management (RMM) tool, not just NinjaRMM from NinjaOne, but generally speaking, they are all designed to run from one. Scripts that are more generic, which may be run from an RMM but don’t have any specific RMM details, or are useful outside of an RMM context, are instead in my [MSP-Scripts](https://github.com/dszp/MSP-Scripts) repository.