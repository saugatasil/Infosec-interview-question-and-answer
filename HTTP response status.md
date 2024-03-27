
Security Headeer
    https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

Informational responses (100 – 199)
Successful responses (200 – 299)
Redirection messages (300 – 399)
Client error responses (400 – 499)
Server error responses (500 – 599)

https://developer.mozilla.org/en-US/docs/Web/HTTP/Status#server_error_responses

================================================
Informational responses (100 – 199)
============================================


========================================
Successful responses (200 – 299)
======================================

200 OK
----------------------------------
The request succeeded. The result meaning of "success" depends on the HTTP method:

GET: The resource has been fetched and transmitted in the message body.
HEAD: The representation headers are included in the response without any message body.
PUT or POST: The resource describing the result of the action is transmitted in the message body.
TRACE: The message body contains the request message as received by the server.


202 Accepted
----------------------------------
The request has been received but not yet acted upon. It is noncommittal, since there is no way in HTTP to later send an asynchronous response indicating the outcome of the request. It is intended for cases where another process or server handles the request, or for batch processing.

203 Non-Authoritative Information
----------------------------------
This response code means the returned metadata is not exactly the same as is available from the origin server, but is collected from a local or a third-party copy. This is mostly used for mirrors or backups of another resource. Except for that specific case, the 200 OK response is preferred to this status.


====================================
Redirection messages (300 – 399)
====================================

302 Found
----------------------------------
This response code means that the URI of requested resource has been changed temporarily. Further changes in the URI might be made in the future. Therefore, this same URI should be used by the client in future requests.


========================================
Client error responses (400 – 499)
========================================

402 Payment Required Experimental
----------------------------------
This response code is reserved for future use. The initial aim for creating this code was using it for digital payment systems, however this status code is used very rarely and no standard convention exists.

403 Forbidden
----------------------------------
The client does not have access rights to the content; that is, it is unauthorized, so the server is refusing to give the requested resource. Unlike 401 Unauthorized, the client's identity is known to the server.

404 Not Found
----------------------------------
The server cannot find the requested resource. In the browser, this means the URL is not recognized. In an API, this can also mean that the endpoint is valid but the resource itself does not exist. Servers may also send this response instead of 403 Forbidden to hide the existence of a resource from an unauthorized client. This response code is probably the most well known due to its frequent occurrence on the web.


=====================================
Server error responses (500 – 599)
====================================

500 Internal Server Error
----------------------------------
The server has encountered a situation it does not know how to handle.

502 Bad Gateway
----------------------------------
This error response means that the server, while working as a gateway to get a response needed to handle the request, got an invalid response.

503 Service Unavailable
----------------------------------
The server is not ready to handle the request. Common causes are a server that is down for maintenance or that is overloaded. Note that together with this response, a user-friendly page explaining the problem should be sent. This response should be used for temporary conditions and the Retry-After HTTP header should, if possible, contain the estimated time before the recovery of the service. The webmaster must also take care about the caching-related headers that are sent along with this response, as these temporary condition responses should usually not be cached.


==============================================================
CONNECT
    The HTTP CONNECT method starts two-way communications with the requested resource. It can be used to open a tunnel.

DELETE
    The HTTP DELETE request method deletes the specified resource.

GET
    The HTTP GET method requests a representation of the specified resource. Requests using GET should only be used to request data (they shouldn't include data).

POST
    The HTTP POST method sends data to the server. The type of the body of the request is indicated by the Content-Type header.

HEAD
    The HTTP HEAD method requests the headers that would be returned if the HEAD request's URL was instead requested with the HTTP GET method. For example, if a URL might produce a large download, a HEAD request could read its Content-Length header to check the filesize without actually downloading the file.

OPTIONS
    The HTTP OPTIONS method requests permitted communication options for a given URL or server. A client can specify a URL with this method, or an asterisk (*) to refer to the entire server.

PATCH
    The HTTP PATCH request method applies partial modifications to a resource.

PUT
    The HTTP PUT request method creates a new resource or replaces a representation of the target resource with the request payload.

TRACE
    The HTTP TRACE method performs a message loop-back test along the path to the target resource, providing a useful debugging mechanism.




