library(lattice)

csvDataFrame <- read.table("iperf_plot1.csv",header=TRUE)

trellis.device("svg", file="throughput.svg", color=T, width=6.5, height=5.0)

xyplot(throughput ~ time, group=port, csvDataFrame, type=c("p","g","o"), 
       pch=20, auto.key=TRUE, xlab="time[s]", ylab="throughput [Kbit/s]")

dev.off() -> null

trellis.device("svg", file="retry.svg", color=T, width=6.5, height=5.0)

xyplot(retry ~ time, group=port, csvDataFrame, type=c("p","g","o"), 
       pch=20, auto.key=TRUE, xlab="time[s]", ylab="# retrires")

dev.off() -> null
