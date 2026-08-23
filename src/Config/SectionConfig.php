<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Config;

/**
 * Class SectionConfig
 *
 * Base for the typed configuration sections.
 *
 * Every option is a fluent accessor: calling it with no argument reads, calling it
 * with one writes and returns $this. Reads and writes are told apart with
 * func_num_args() rather than a null default, so options that are legitimately
 * nullable — storage.dir, content.length.max — can actually be set back to null.
 *
 * Subclasses declare their dotted-key to accessor map once; fill() and toArray()
 * are derived from it.
 *
 * @package Laika\Shield\Config
 */
abstract class SectionConfig
{
    /**
     * Map of the public dotted config key to the accessor implementing it.
     *
     * @return array<string,string>
     */
    abstract protected function keyMap(): array;

    /**
     * Apply only the keys present in $values, leaving every other option at its
     * default. This is what makes a partial config merge instead of replacing:
     * supplying request.filter's content.length.max must not wipe its
     * blocked.methods.
     *
     * @param array<string,mixed> $values
     * @return static
     */
    public function fill(array $values): static
    {
        foreach ($this->keyMap() as $key => $accessor) {
            // array_key_exists, not isset — an explicit null is a value, not an absence.
            if (array_key_exists($key, $values)) {
                $this->{$accessor}($values[$key]);
            }
        }

        return $this;
    }

    /**
     * The section as a dotted-key array, for the static Config facade.
     *
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        $out = [];

        foreach ($this->keyMap() as $key => $accessor) {
            $out[$key] = $this->{$accessor}();
        }

        return $out;
    }

    /**
     * Whether this section exposes the given dotted key.
     */
    public function hasKey(string $key): bool
    {
        return array_key_exists($key, $this->keyMap());
    }

    /**
     * Read or write a single option by its dotted key.
     *
     * @param  mixed ...$value Pass nothing to read, one argument to write.
     * @return mixed
     */
    public function option(string $key, mixed ...$value): mixed
    {
        $accessor = $this->keyMap()[$key] ?? null;

        if ($accessor === null) {
            return null;
        }

        return $value === [] ? $this->{$accessor}() : $this->{$accessor}($value[0]);
    }
}
