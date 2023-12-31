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

// DescribeRouterInterfaces invokes the vpc.DescribeRouterInterfaces API synchronously
func (client *Client) DescribeRouterInterfaces(request *DescribeRouterInterfacesRequest) (response *DescribeRouterInterfacesResponse, err error) {
	response = CreateDescribeRouterInterfacesResponse()
	err = client.DoAction(request, response)
	return
}

// DescribeRouterInterfacesWithChan invokes the vpc.DescribeRouterInterfaces API asynchronously
func (client *Client) DescribeRouterInterfacesWithChan(request *DescribeRouterInterfacesRequest) (<-chan *DescribeRouterInterfacesResponse, <-chan error) {
	responseChan := make(chan *DescribeRouterInterfacesResponse, 1)
	errChan := make(chan error, 1)
	err := client.AddAsyncTask(func() {
		defer close(responseChan)
		defer close(errChan)
		response, err := client.DescribeRouterInterfaces(request)
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

// DescribeRouterInterfacesWithCallback invokes the vpc.DescribeRouterInterfaces API asynchronously
func (client *Client) DescribeRouterInterfacesWithCallback(request *DescribeRouterInterfacesRequest, callback func(response *DescribeRouterInterfacesResponse, err error)) <-chan int {
	result := make(chan int, 1)
	err := client.AddAsyncTask(func() {
		var response *DescribeRouterInterfacesResponse
		var err error
		defer close(result)
		response, err = client.DescribeRouterInterfaces(request)
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

// DescribeRouterInterfacesRequest is the request struct for api DescribeRouterInterfaces
type DescribeRouterInterfacesRequest struct {
	*requests.RpcRequest
	ResourceOwnerId        requests.Integer                  `position:"Query" name:"ResourceOwnerId"`
	IncludeReservationData requests.Boolean                  `position:"Query" name:"IncludeReservationData"`
	PageNumber             requests.Integer                  `position:"Query" name:"PageNumber"`
	ResourceGroupId        string                            `position:"Query" name:"ResourceGroupId"`
	PageSize               requests.Integer                  `position:"Query" name:"PageSize"`
	ResourceOwnerAccount   string                            `position:"Query" name:"ResourceOwnerAccount"`
	OwnerId                requests.Integer                  `position:"Query" name:"OwnerId"`
	Tags                   *[]DescribeRouterInterfacesTags   `position:"Query" name:"Tags"  type:"Repeated"`
	Filter                 *[]DescribeRouterInterfacesFilter `position:"Query" name:"Filter"  type:"Repeated"`
}

// DescribeRouterInterfacesTags is a repeated param struct in DescribeRouterInterfacesRequest
type DescribeRouterInterfacesTags struct {
	Value string `name:"Value"`
	Key   string `name:"Key"`
}

// DescribeRouterInterfacesFilter is a repeated param struct in DescribeRouterInterfacesRequest
type DescribeRouterInterfacesFilter struct {
	Value *[]string `name:"Value" type:"Repeated"`
	Key   string    `name:"Key"`
}

// DescribeRouterInterfacesResponse is the response struct for api DescribeRouterInterfaces
type DescribeRouterInterfacesResponse struct {
	*responses.BaseResponse
	RequestId          string             `json:"RequestId" xml:"RequestId"`
	PageNumber         int                `json:"PageNumber" xml:"PageNumber"`
	PageSize           int                `json:"PageSize" xml:"PageSize"`
	TotalCount         int                `json:"TotalCount" xml:"TotalCount"`
	RouterInterfaceSet RouterInterfaceSet `json:"RouterInterfaceSet" xml:"RouterInterfaceSet"`
}

// CreateDescribeRouterInterfacesRequest creates a request to invoke DescribeRouterInterfaces API
func CreateDescribeRouterInterfacesRequest() (request *DescribeRouterInterfacesRequest) {
	request = &DescribeRouterInterfacesRequest{
		RpcRequest: &requests.RpcRequest{},
	}
	request.InitWithApiInfo("Vpc", "2016-04-28", "DescribeRouterInterfaces", "vpc", "openAPI")
	request.Method = requests.POST
	return
}

// CreateDescribeRouterInterfacesResponse creates a response to parse from DescribeRouterInterfaces response
func CreateDescribeRouterInterfacesResponse() (response *DescribeRouterInterfacesResponse) {
	response = &DescribeRouterInterfacesResponse{
		BaseResponse: &responses.BaseResponse{},
	}
	return
}
