<?php

namespace Sammyjo20\Saloon\Tests\Resources\Requests;

use Sammyjo20\Saloon\Constants\Saloon;
use Sammyjo20\Saloon\Http\SaloonRequest;
use Sammyjo20\Saloon\Tests\Resources\Connectors\CustomResponseConnector;
use Sammyjo20\Saloon\Tests\Resources\Plugins\HasTestHandler;

class CustomResponseConnectorRequest extends SaloonRequest
{
	use HasTestHandler;

	/**
	 * Define the method that the request will use.
	 *
	 * @var string|null
	 */
	protected ?string $method = Saloon::GET;

	/**
	 * The connector.
	 *
	 * @var string|null
	 */
	protected ?string $connector = CustomResponseConnector::class;

	/**
	 * Define the endpoint for the request.
	 *
	 * @return string
	 */
	public function defineEndpoint(): string
	{
		return '/user';
	}
}
