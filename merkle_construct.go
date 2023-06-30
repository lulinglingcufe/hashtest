package main

import (
	 "fmt"
	"math"
	"math/rand"
	 merkletree "github.com/wealdtech/go-merkletree"
	 "github.com/wealdtech/go-merkletree/keccak256"
	 "time"
	 "encoding/json"
	 "io/ioutil"
)

// 将tree结构体存储为文件
func saveMerkleTreeToFile(tree *merkletree.MerkleTree, filePath string) error {
	// 将tree结构体转换为JSON格式
	jsonData, err := json.Marshal(tree)
	if err != nil {
		return err
	}

	// 将JSON数据写入文件
	err = ioutil.WriteFile(filePath, jsonData, 0644)
	if err != nil {
		return err
	}

	return nil
}

const _letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const _letterslen = len(_letters)

func _randomString(n int) string {
	res := make([]byte, n)
	for i := range res {
		res[i] = _letters[rand.Int63()%int64(_letterslen)]
	}
	return string(res)
}

// Example using the Merkle tree to generate and verify proofs.
func main() {

	var  dataItems int = 5000//4096 1000000  500000
	var  shard_granularity uint64 =  5000//500000//5000  //分片粒度    10000   5000 20000 5000   10000

	//proofs := 10//1234//291   查询位置的数量
	data := make([][]byte, dataItems) //数据初始化
	for i := 0; i < dataItems; i++ {
		data[i] = []byte(_randomString(700))
	}

	start := time.Now() // 获取当前时间（构建索引的同时，SP构建merkle tree）

    //构造hash tree，这个是一开始create index之后就要做的事情。
	//如果进行分片，那么需要构造 多棵树。我用一个列表 tree_ptr 放这些树。
	shard_number  := uint64(math.Ceil( float64(dataItems)/float64(shard_granularity))) //分片的组数
	tree_ptr := make([]*merkletree.MerkleTree, shard_number)

	basePath := "/home/ubuntu/zgc/projects/src/hashtest/ads/ads_"




	var temp_j uint64 = 0
	for j := temp_j; j < shard_number; j++ {
		tree, err := merkletree.NewUsing(data[j* shard_granularity:(j+1)* shard_granularity],keccak256.New(), false)

		filePath := fmt.Sprintf("%s%d", basePath, j)
		saveMerkleTreeToFile(tree,filePath)

		if err != nil {
			panic(err)
		}
		tree_ptr[j] = tree
		//fmt.Printf("This is j : %v \n",j)
	}
	elapsed := time.Since(start)
    fmt.Println("SP construct merkle tree Time : ", elapsed)
	
}
