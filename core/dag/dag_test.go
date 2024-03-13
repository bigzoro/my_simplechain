// Copyright 2020 The go-simplechain Authors
// This file is part of the go-simplechain library.
//
// The go-simplechain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-simplechain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-simplechain library. If not, see <http://www.gnu.org/licenses/>.

package dag

import (
	"fmt"
	"os"
	"testing"

	"github.com/bigzoro/my_simplechain/log"
)

func TestDag(t *testing.T) {

	log.Root().SetHandler(log.CallerFileHandler(log.LvlFilterHandler(log.Lvl(4), log.StreamHandler(os.Stderr, log.TerminalFormat(true)))))
	dag := NewDag(10)
	dag.AddEdge(0, 1)
	dag.AddEdge(0, 2)
	dag.AddEdge(3, 4)
	dag.AddEdge(3, 5)
	dag.AddEdge(1, 6)
	dag.AddEdge(2, 6)
	dag.AddEdge(4, 6)
	dag.AddEdge(5, 6)
	dag.AddEdge(6, 7)
	dag.AddEdge(7, 8)
	dag.AddEdge(7, 9)

	buff, err := dag.Print()
	if err != nil {
		fmt.Print("print DAG Graph error!", err)
	}
	fmt.Printf("DAG Graph for blockNumber:%d\n%s", 1, buff.String())

	fmt.Printf("iterate over second times")
	for dag.HasNext() {
		ids := dag.Next()
		fmt.Printf("ids:%+v", ids)
	}

}
