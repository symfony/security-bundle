<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Bundle\SecurityBundle\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Security\Core\Dumper\MermaidDirectionEnum;
use Symfony\Component\Security\Core\Dumper\MermaidDumper;
use Symfony\Component\Security\Core\Role\RoleHierarchyInterface;

/**
 * Command to dump the role hierarchy as a Mermaid flowchart.
 *
 * @author Damien Fernandes <damien.fernandes24@gmail.com>
 */
#[AsCommand(name: 'debug:security:role-hierarchy', description: 'Dump the role hierarchy as a Mermaid flowchart')]
class SecurityRoleHierarchyDumpCommand extends Command
{
    public function __construct(
        private readonly RoleHierarchyInterface $roleHierarchy,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->setDefinition([
                new InputOption(
                    'direction',
                    'd',
                    InputOption::VALUE_REQUIRED,
                    'The direction of the flowchart ['.implode('|', $this->getAvailableDirections()).']',
                    MermaidDirectionEnum::TOP_TO_BOTTOM->value,
                    $this->getAvailableDirections()
                ),
            ])
            ->setHelp(<<<'USAGE'
                The <info>%command.name%</info> command dumps the role hierarchy in Mermaid format.

                <info>Mermaid</info>: %command.full_name% > roles.mmd
                <info>Mermaid with direction</info>: %command.full_name% --direction=BT > roles.mmd
                USAGE
            )
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        if (null === $this->roleHierarchy) {
            $io->getErrorStyle()->writeln('<comment>No role hierarchy is configured.</comment>');

            return Command::SUCCESS;
        }

        $direction = $input->getOption('direction');

        if (!MermaidDirectionEnum::tryFrom($direction)) {
            $io->getErrorStyle()->writeln(\sprintf('<error>Invalid direction, available options are "%s"</error>', implode('"', $this->getAvailableDirections())));

            return Command::FAILURE;
        }

        $dumper = new MermaidDumper();
        $mermaidOutput = $dumper->dump($this->roleHierarchy, MermaidDirectionEnum::from($direction));

        $output->writeln($mermaidOutput, OutputInterface::OUTPUT_RAW);

        return Command::SUCCESS;
    }

    /**
     * @return string[]
     */
    private function getAvailableDirections(): array
    {
        return array_map(fn ($case) => $case->value, MermaidDirectionEnum::cases());
    }
}
