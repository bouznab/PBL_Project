library(lattice)

read.table("stats.csv", header=TRUE) -> csvDataFrameSource
csvDataFrame <- csvDataFrameSource
read.table("stats2.csv", header=TRUE) -> csvDataFrameSource2
csvDataFrame2 <- csvDataFrameSource2

trellis.device("pdf", file="graph1.pdf", color=T, width=6.5, height=5.0)

# ... xyplot here
xyplot(latency ~ ping, data=csvDataFrame,
       type=c("p","g","o"), pch=8)

dev.off() -> null

trellis.device("pdf", file="graph2.pdf", color=T, width=6.5, height=5.0)

# ... xyplot here
xyplot(latency ~ ping, data=csvDataFrame2,
       type=c("p","g","o"),pch=8)

dev.off() -> null
