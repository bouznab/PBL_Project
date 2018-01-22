library(lattice)

read.table("stats.csv", header=TRUE) -> csvDataFrameSource
csvDataFrame <- csvDataFrameSource

trellis.device("pdf", file="/media/sf_PBL-Project/graph1.pdf", color=T, width=6.5, height=5.0)

# ... xyplot here
xyplot(latency ~ ping, data=csvDataFrame,
       type=c("p","g","o"), pch=8)

dev.off() -> null 

#trellis.device("pdf", file="graph2.pdf", color=T, width=6.5, height=5.0)

# ... xyplot here
#xyplot(latency ~ requests, data=csvDataFrame,
#       type=c("p","g","o"),pch=8,
#       xlab="response rate [rsp/s]", ylab="latency [ms]")

#dev.off() -> null 
