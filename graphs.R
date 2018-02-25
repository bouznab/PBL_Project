library(lattice)

csvDataFrame <- read.table("stats.csv",header=TRUE)

trellis.device("pdf", file="ping.pdf", color=T, width=6.5, height=5.0)

# ... xyplot here
xyplot(latency ~ ping, group=port, data=csvDataFrame,
       type=c("p","g","o"), pch=8, auto.key=TRUE )

dev.off() -> null
