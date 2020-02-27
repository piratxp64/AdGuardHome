import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withNamespaces } from 'react-i18next';
import ReactTable from 'react-table';

import {
    checkFiltered,
    checkRewrite,
    checkWhiteList,
} from '../../helpers/helpers';
import { TABLE_DEFAULT_PAGE_SIZE } from '../../helpers/constants';
import getDateCell from './Cells/getDateCell';
import getDomainCell from './Cells/getDomainCell';
import getClientCell from './Cells/getClientCell';
import getResponseCell from './Cells/getResponseCell';
import Card from '../ui/Card';

class Table extends Component {
    columns = [
        {
            Header: this.props.t('time_table_header'),
            accessor: 'time',
            minWidth: 105,
            Cell: getDateCell,
        },
        {
            Header: this.props.t('domain_name_table_header'),
            accessor: 'domain',
            minWidth: 180,
            Cell: getDomainCell,
        },
        {
            Header: this.props.t('response_table_header'),
            accessor: 'response',
            minWidth: 250,
            Cell: getResponseCell(this.props.filtering, this.props.t),
        },
        {
            Header: this.props.t('client_table_header'),
            accessor: 'client',
            maxWidth: 240,
            minWidth: 240,
            Cell: getClientCell(this.props.t),
        },
    ];


    fetchData = (state) => {
        const { pages } = state;
        const { oldest, page, getLogs } = this.props;
        const isLastPage = pages && (page + 1 === pages);

        if (isLastPage) {
            getLogs(oldest, page);
        }
    };

    changePage = (page) => {
        this.props.setLogsPage(page);
        this.props.setLogsPagination({ page, pageSize: TABLE_DEFAULT_PAGE_SIZE });
    };

    render() {
        const {
            t,
            processingGetLogs,
            processingGetConfig,
            logs,
            pages,
            page,
        } = this.props;
        const isLoading = processingGetLogs || processingGetConfig;

        return (
            <Card>
                <ReactTable
                    manual
                    minRows={5}
                    page={page}
                    pages={pages}
                    columns={this.columns}
                    filterable={false}
                    sortable={false}
                    data={logs || []}
                    loading={isLoading}
                    showPagination={true}
                    showPaginationTop={true}
                    showPageJump={false}
                    showPageSizeOptions={false}
                    onFetchData={this.fetchData}
                    onPageChange={this.changePage}
                    className="logs__table"
                    defaultPageSize={TABLE_DEFAULT_PAGE_SIZE}
                    previousText={t('previous_btn')}
                    nextText={t('next_btn')}
                    loadingText={t('loading_table_status')}
                    rowsText={t('rows_table_footer_text')}
                    noDataText={t('no_logs_found')}
                    pageText={''}
                    ofText={''}
                    renderTotalPagesCount={() => false}
                    defaultFilterMethod={(filter, row) => {
                        const id = filter.pivotId || filter.id;
                        return row[id] !== undefined
                            ? String(row[id]).indexOf(filter.value) !== -1
                            : true;
                    }}
                    defaultSorted={[
                        {
                            id: 'time',
                            desc: true,
                        },
                    ]}
                    getTrProps={(_state, rowInfo) => {
                        if (!rowInfo) {
                            return {};
                        }

                        const { reason } = rowInfo.original;

                        if (checkFiltered(reason)) {
                            return {
                                className: 'red',
                            };
                        } else if (checkWhiteList(reason)) {
                            return {
                                className: 'green',
                            };
                        } else if (checkRewrite(reason)) {
                            return {
                                className: 'blue',
                            };
                        }

                        return {
                            className: '',
                        };
                    }}
                />
            </Card>
        );
    }
}

Table.propTypes = {
    logs: PropTypes.array.isRequired,
    pages: PropTypes.number.isRequired,
    page: PropTypes.number.isRequired,
    oldest: PropTypes.string.isRequired,
    filtering: PropTypes.object.isRequired,
    processingGetLogs: PropTypes.bool.isRequired,
    processingGetConfig: PropTypes.bool.isRequired,
    setLogsPage: PropTypes.func.isRequired,
    setLogsPagination: PropTypes.func.isRequired,
    getLogs: PropTypes.func.isRequired,
    t: PropTypes.func.isRequired,
};

export default withNamespaces()(Table);
