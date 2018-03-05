library(lattice)

csvDataFrame <- read.table("stats.csv",header=TRUE)

trellis.device(device="svg", file="ping.svg", color=T, width=6.5, height=5.0)

# ... xyplot here
xyplot(latency ~ ping, group=port, data=csvDataFrame,
       type=c("p","g","o"), pch=20, auto.key=TRUE, 
       xlab="ping", ylab="latency[ms]")

dev.off() -> null
