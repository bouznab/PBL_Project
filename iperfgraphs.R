library(lattice)

csvDataFrame <- read.table("iperf_plot.csv",header=TRUE)

trellis.device("pdf", file="iperf.pdf", color=T, width=6.5, height=5.0)

xyplot(retry ~ time, group=port, csvDataFrame, type=c("p","g","o"), 
       pch=8, auto.key=TRUE)

dev.off() -> null
