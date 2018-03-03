library(lattice)

csvDataFrame <- read.table("iperf_plot1.csv",header=TRUE)

trellis.device("svg", file="iperf.svg", color=T, width=6.5, height=5.0)

xyplot(retry ~ time, group=port, csvDataFrame, type=c("p","g","o"), 
       pch=20, auto.key=TRUE, xlab="time[s]", ylab="# retries")

dev.off() -> null
