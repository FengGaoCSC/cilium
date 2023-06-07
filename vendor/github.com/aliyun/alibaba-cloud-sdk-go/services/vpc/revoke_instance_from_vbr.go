package vpc

//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//
// Code generated by Alibaba Cloud SDK Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/responses"
)

// RevokeInstanceFromVbr invokes the vpc.RevokeInstanceFromVbr API synchronously
func (client *Client) RevokeInstanceFromVbr(request *RevokeInstanceFromVbrRequest) (response *RevokeInstanceFromVbrResponse, err error) {
	response = CreateRevokeInstanceFromVbrResponse()
	err = client.DoAction(request, response)
	return
}

// RevokeInstanceFromVbrWithChan invokes the vpc.RevokeInstanceFromVbr API asynchronously
func (client *Client) RevokeInstanceFromVbrWithChan(request *RevokeInstanceFromVbrRequest) (<-chan *RevokeInstanceFromVbrResponse, <-chan error) {
	responseChan := make(chan *RevokeInstanceFromVbrResponse, 1)
	errChan := make(chan error, 1)
	err := client.AddAsyncTask(func() {
		defer close(responseChan)
		defer close(errChan)
		response, err := client.RevokeInstanceFromVbr(request)
		if err != nil {
			errChan <- err
		} else {
			responseChan <- response
		}
	})
	if err != nil {
		errChan <- err
		close(responseChan)
		close(errChan)
	}
	return responseChan, errChan
}

// RevokeInstanceFromVbrWithCallback invokes the vpc.RevokeInstanceFromVbr API asynchronously
func (client *Client) RevokeInstanceFromVbrWithCallback(request *RevokeInstanceFromVbrRequest, callback func(response *RevokeInstanceFromVbrResponse, err error)) <-chan int {
	result := make(chan int, 1)
	err := client.AddAsyncTask(func() {
		var response *RevokeInstanceFromVbrResponse
		var err error
		defer close(result)
		response, err = client.RevokeInstanceFromVbr(request)
		callback(response, err)
		result <- 1
	})
	if err != nil {
		defer close(result)
		callback(nil, err)
		result <- 0
	}
	return result
}

// RevokeInstanceFromVbrRequest is the request struct for api RevokeInstanceFromVbr
type RevokeInstanceFromVbrRequest struct {
	*requests.RpcRequest
	VbrOwnerUid    string    `position:"Query" name:"VbrOwnerUid"`
	VbrRegionNo    string    `position:"Query" name:"VbrRegionNo"`
	VbrInstanceIds *[]string `position:"Query" name:"VbrInstanceIds"  type:"Repeated"`
	GrantType      string    `position:"Query" name:"GrantType"`
	InstanceId     string    `position:"Query" name:"InstanceId"`
}

// RevokeInstanceFromVbrResponse is the response struct for api RevokeInstanceFromVbr
type RevokeInstanceFromVbrResponse struct {
	*responses.BaseResponse
	RequestId string `json:"RequestId" xml:"RequestId"`
}

// CreateRevokeInstanceFromVbrRequest creates a request to invoke RevokeInstanceFromVbr API
func CreateRevokeInstanceFromVbrRequest() (request *RevokeInstanceFromVbrRequest) {
	request = &RevokeInstanceFromVbrRequest{
		RpcRequest: &requests.RpcRequest{},
	}
	request.InitWithApiInfo("Vpc", "2016-04-28", "RevokeInstanceFromVbr", "vpc", "openAPI")
	request.Method = requests.POST
	return
}

// CreateRevokeInstanceFromVbrResponse creates a response to parse from RevokeInstanceFromVbr response
func CreateRevokeInstanceFromVbrResponse() (response *RevokeInstanceFromVbrResponse) {
	response = &RevokeInstanceFromVbrResponse{
		BaseResponse: &responses.BaseResponse{},
	}
	return
}