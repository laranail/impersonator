<?php

declare(strict_types=1);

namespace Simtabi\Laranail\Impersonator\Laravel\Commands;

use Illuminate\Console\Command;
use Simtabi\Laranail\Impersonator\Core\Exceptions\AuditRowMissing;
use Simtabi\Laranail\Impersonator\Laravel\Audit\AuditExporter;
use Simtabi\Laranail\Impersonator\Laravel\Commands\Concerns\SupportsNamespacedNames;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Exports one impersonation and its action trail, for a compliance request.
 *
 * Writes to a file when given one and to stdout otherwise, so it composes with a pipe. The
 * export never contains the credential hash or the session id — see AuditExporter.
 */
class ExportAuditCommand extends Command
{
    use SupportsNamespacedNames;

    protected $description = 'Export an impersonation audit row and its full action trail';

    public function handle(AuditExporter $exporter): int
    {
        $audit = $this->stringArgument('audit');
        $format = strtolower($this->stringOption('format') ?? AuditExporter::JSON);

        if (! in_array($format, AuditExporter::formats(), true)) {
            $this->components->error(sprintf(
                'Unknown format [%s]. Available: %s.',
                $format,
                implode(', ', AuditExporter::formats()),
            ));

            return self::INVALID;
        }

        try {
            $document = $exporter->export($audit, $format);
        } catch (AuditRowMissing $missing) {
            $this->components->error($missing->getMessage());

            return self::FAILURE;
        }

        $path = $this->stringOption('output');

        if ($path === null) {
            // Straight to stdout with no decoration, so the output is the document and nothing
            // else — otherwise a pipe into `jq` gets a banner it cannot parse.
            $this->output->writeln($document, OutputInterface::OUTPUT_RAW);

            return self::SUCCESS;
        }

        if (file_put_contents($path, $document) === false) {
            $this->components->error(sprintf('Could not write the export to [%s].', $path));

            return self::FAILURE;
        }

        $this->components->info(sprintf('Exported impersonation [%s] to %s.', $audit, $path));

        return self::SUCCESS;
    }

    protected function namespacedSignature(): string
    {
        return 'laranail::impersonator.export-audit
            {audit : the audit row id}
            {--format=json : json or csv}
            {--output= : write to this file instead of stdout}';
    }
}
