<?php

namespace Helori\PhpSign\Elements;

use Helori\PhpSign\Exceptions\ValidationException;
use Helori\PhpSign\Drivers\DriverInterface;


class Requester
{
    /**
     * The driver that will be used
     *
     * @var \Helori\PhpSign\Drivers\DriverInterface
     */
    protected $driver;

    /**
     * Create a new Requester instance.
     *
     * @param  string  $driverName
     * @param  array  $driverConfig
     * @return void
     */
    public function __construct(string $driverName, array $driverConfig)
    {
        $name = '\\Helori\\PhpSign\\Drivers\\'.ucfirst(strtolower($driverName)).'Driver';

        if(class_exists($name) && is_subclass_of($name, DriverInterface::class)){

            $this->driver = new $name($driverConfig);

        }else{

            throw new ValidationException('Unknown driver name "'.$driverName.'" with class name "'.$name.'"');
        }
    }

    /**
     * Initialize a transaction from a scenario
     *
     * @param  Scenario  $scenario
     * @return array
     */
    public function initTransaction(Scenario $scenario)
    {
        return $this->driver->initTransaction($scenario);
    }
}